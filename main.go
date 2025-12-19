package main

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"

	"flaregate/internal/config"
	"flaregate/internal/cloudflare"
	"flaregate/internal/tunnel"
)

//go:embed templates/* static/*
var f embed.FS

var LogFile = "data/cloudflared.log"
var runner *tunnel.Runner

// loadEnvironmentVariables loads configuration from environment variables
func loadEnvironmentVariables() {
	// Check if running in Docker (common indicators)
	isDocker := false
	if _, err := os.Stat("/.dockerenv"); err == nil {
		isDocker = true
		log.Println("[Init] Detected Docker environment")
	}

	// Check data directory permissions (important for Docker)
	checkDataDirectory(isDocker)

	// Validate critical environment variables and provide helpful guidance
	validateRequiredEnvVars(isDocker)
}

// checkDataDirectory verifies data directory is writable
func checkDataDirectory(isDocker bool) {
	dataDir := "data"

	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Printf("[Init] Error creating data directory: %v", err)
		return
	}

	// Test write permissions
	testFile := filepath.Join(dataDir, ".permission_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		log.Printf("[Init] ERROR: Data directory is not writable: %v", err)
		if isDocker {
			log.Println("[Init] Docker Setup Issue:")
			log.Println("  Ensure volume mount has correct permissions:")
			log.Println("  docker run -v ./data:/app/data:Z ...")
		}
		return
	}

	// Clean up test file
	os.Remove(testFile)

	if isDocker {
		log.Println("[Init] Data directory permissions OK")
	}
}

// validateRequiredEnvVars checks and reports environment variables
func validateRequiredEnvVars(isDocker bool) {
	// Check if SECRET_KEY is set (optional)
	secretKey := os.Getenv("SECRET_KEY")
	if secretKey != "" {
		log.Printf("[Init] Using SECRET_KEY from environment")
	} else {
		log.Printf("[Init] SECRET_KEY not set, will auto-generate")
	}

	// Check if PORT is set (optional - defaults to 8020)
	port := os.Getenv("PORT")
	if port != "" {
		log.Printf("[Init] Using PORT=%s from environment", port)
	} else {
		log.Printf("[Init] Using default PORT=8020")
	}

	if isDocker {
		log.Println("[Init] Running in Docker environment")
	}
}

// printLoginInfo displays login information based on user system state
func printLoginInfo(port string) {
	hasUsers := config.HasUsers()

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🔐 FlareGate Dashboard Login Information")
	fmt.Println(strings.Repeat("=", 60))

	if hasUsers {
		fmt.Println("👤 User account exists in database")
		fmt.Println("   Please use your existing credentials to login")
	} else {
		fmt.Println("🚀 No user found - Setup Required!")
		fmt.Println("   Visit dashboard to create your account")
		fmt.Println("   Registration page will be displayed automatically")
	}

	fmt.Printf("🌐 Dashboard URL: http://localhost:%s\n", port)
	fmt.Println(strings.Repeat("=", 60))
}

// contains checks if a string exists in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func main() {
	// Load Environment Variables
	loadEnvironmentVariables()

	// Init Internal Packages
	config.InitDB()
	runner = tunnel.NewRunner(LogFile)

	// Attempt Auto Start for user tunnel
	if cfg, err := config.GetAppConfig(); err == nil {
		go func() {
			fmt.Println("[Init] Config found, starting tunnel...")
			if err := runner.Start(cfg); err != nil {
				fmt.Printf("[Init] Failed to start tunnel: %v\n", err)
			}
		}()
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.SetTrustedProxies(nil)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8020"
	}
	secretKey := getOrCreateSecretKey()

	// Print login information
	printLoginInfo(port)

	// Session Middleware
	gob.Register(map[string]interface{}{})
	store := cookie.NewStore([]byte(secretKey))

	// Configure cookie options for Docker compatibility
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   false,    // Important for HTTP access (not HTTPS)
		SameSite: http.SameSiteLaxMode,
		Domain:   "",       // Allow all domains
	})

	r.Use(sessions.Sessions("mysession", store))

	// Static & Templates
	staticFS, err := fs.Sub(f, "static")
	if err != nil {
		log.Fatal(err)
	}
	r.StaticFS("/static", http.FS(staticFS))
	
	// Load Templates from Embed FS (Including Partials)
	// Note: We use ParseFS to load ALL templates including partials pattern
	tmpl := template.Must(template.New("").Funcs(r.FuncMap).ParseFS(f, "templates/*.html", "templates/partials/*.html"))
	r.SetHTMLTemplate(tmpl)

	// Global Context Middleware
	r.Use(func(c *gin.Context) {
		cfg, _ := config.GetAppConfig()
		if cfg != nil {
			c.Set("TunnelName", cfg.TunnelName)
		}
		c.Next()
	})

	r.NoRoute(func(c *gin.Context) {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"Code":    http.StatusNotFound,
			"Message": "The page you are looking for does not exist.",
		})
	})

	// Auth Middleware
	authRequired := func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")

		// Debug logging for Docker
		log.Printf("[Auth] Checking auth for path: %s, userID: %v", c.Request.URL.Path, userID)

		if userID == nil {
			log.Printf("[Auth] No user session found, redirecting to login")
			if c.Request.Header.Get("X-Requested-With") == "XMLHttpRequest" || strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			} else {
				c.Redirect(http.StatusFound, "/login")
			}
			c.Abort()
			return
		}

		log.Printf("[Auth] User authenticated successfully")
		c.Next()
	}

	// Debug endpoint to check session status
	r.GET("/debug-session", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		username := session.Get("username")

		hasUsers := config.HasUsers()
		user, _ := config.GetUser()

		log.Printf("[Debug] Session - userID: %v, username: %v, hasUsers: %v", userID, username, hasUsers)

		c.JSON(http.StatusOK, gin.H{
			"session_user_id":   userID,
			"session_username":  username,
			"has_users":         hasUsers,
			"db_user_id":        user.ID,
			"db_username":       user.Username,
			"cookies":           c.Request.Cookies(),
		})
	})

	// Login Routes
	r.GET("/login", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("user_id") != nil {
			c.Redirect(http.StatusFound, "/")
			return
		}

		// If no user exists, redirect to registration
		if !config.HasUsers() {
			c.Redirect(http.StatusFound, "/register")
			return
		}

		c.HTML(http.StatusOK, "login.html", gin.H{})
	})

	r.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		log.Printf("[Login] Login attempt for username: %s", username)

		user, err := config.ValidateUser(username, password)
		if err != nil {
			log.Printf("[Login] Failed login attempt for username: %s, error: %v", username, err)
			c.HTML(http.StatusOK, "login.html", gin.H{"error": "Invalid credentials"})
			return
		}

		session := sessions.Default(c)
		session.Set("user_id", user.ID)
		session.Set("username", user.Username)

		if err := session.Save(); err != nil {
			log.Printf("[Login] Error saving session: %v", err)
			c.HTML(http.StatusOK, "login.html", gin.H{"error": "Session error"})
			return
		}

		log.Printf("[Login] Success: username=%s, user_id=%d", user.Username, user.ID)
		log.Printf("[Login] Session data: user_id=%v, username=%v", session.Get("user_id"), session.Get("username"))

		c.Redirect(http.StatusFound, "/")
	})

	r.GET("/logout", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Clear()
		session.Save()
		c.Redirect(http.StatusFound, "/login")
	})

	// Registration Routes
	r.GET("/register", func(c *gin.Context) {
		// If user already exists, redirect to login
		if config.HasUsers() {
			c.Redirect(http.StatusFound, "/login")
			return
		}
		c.HTML(http.StatusOK, "register.html", gin.H{})
	})

	r.POST("/register", func(c *gin.Context) {
		// If user already exists, redirect to login
		if config.HasUsers() {
			c.Redirect(http.StatusFound, "/login")
			return
		}

		username := c.PostForm("username")
		password := c.PostForm("password")
		confirmPassword := c.PostForm("confirm_password")

		if username == "" || password == "" {
			c.HTML(http.StatusOK, "register.html", gin.H{
				"error": "Username and password are required",
			})
			return
		}

		if password != confirmPassword {
			c.HTML(http.StatusOK, "register.html", gin.H{
				"error": "Passwords do not match",
				"username": username,
			})
			return
		}

		if len(password) < 6 {
			c.HTML(http.StatusOK, "register.html", gin.H{
				"error": "Password must be at least 6 characters",
				"username": username,
			})
			return
		}

		user, err := config.CreateUser(username, password)
		if err != nil {
			c.HTML(http.StatusOK, "register.html", gin.H{
				"error": "Failed to create user: " + err.Error(),
				"username": username,
			})
			return
		}

		log.Printf("[Register] Success: created user %s", user.Username)

		// Auto-login after registration
		session := sessions.Default(c)
		session.Set("user_id", user.ID)
		session.Set("username", user.Username)
		session.Save()

		c.Redirect(http.StatusFound, "/")
	})

	// Protected Routes Group
	protected := r.Group("/")
	protected.Use(authRequired)
	{
		protected.GET("/", func(c *gin.Context) {
			cfg, _ := config.GetAppConfig()
			if cfg == nil {
				c.Redirect(http.StatusFound, "/setup")
				return
			}
			// Fetch config for dashboard view
			// This is display only, so no token needed
			url := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/configurations", cfg.AccountID, cfg.TunnelID)
			res, _, _ := cloudflare.Request("GET", url, cfg.APIToken, nil)

			var visibleIngress []interface{}
			if res != nil {
				if success, ok := res["success"].(bool); ok && success {
					resultObj, _ := res["result"].(map[string]interface{})
					configObj, _ := resultObj["config"].(map[string]interface{})
					ingressList, _ := configObj["ingress"].([]interface{})
					for _, item := range ingressList {
						r, ok := item.(map[string]interface{})
						if ok && r["hostname"] != nil {
							visibleIngress = append(visibleIngress, r)
						}
					}
				}
			}

			c.HTML(http.StatusOK, "index.html", gin.H{
				"Configured": true,
				"TunnelName": cfg.TunnelName,
				"Ingress":    visibleIngress,
				"ShowChangeTunnel": true,
				"ActivePage": "dashboard",
				"SystemHostname": cfg.SystemHostname,
				"Port": port,
			})
		})

		protected.GET("/setup", func(c *gin.Context) {
			cfg, _ := config.GetAppConfig()
			if cfg != nil {
				c.Redirect(http.StatusFound, "/")
				return
			}
			c.HTML(http.StatusOK, "setup.html", gin.H{})
		})

		protected.GET("/docs", func(c *gin.Context) {
			cfg, _ := config.GetAppConfig()
			tunnelName := "Unknown"
			if cfg != nil {
				tunnelName = cfg.TunnelName
			}
			c.HTML(http.StatusOK, "docs.html", gin.H{
				"TunnelName": tunnelName,
				"ActivePage": "docs",
			})
		})

		protected.GET("/log", func(c *gin.Context) {
			cfg, _ := config.GetAppConfig()
			tunnelName := "Unknown"
			if cfg != nil {
				tunnelName = cfg.TunnelName
			}
			c.HTML(http.StatusOK, "log.html", gin.H{
				"TunnelName": tunnelName,
				"ShowChangeTunnel": false, 
				"ActivePage": "logs",
			})
		})

		api := protected.Group("/api")
		{
			// Log API
			api.GET("/log", func(c *gin.Context) {
				content, err := os.ReadFile(LogFile)
				if err != nil {
					if os.IsNotExist(err) {
						c.String(http.StatusOK, "No logs yet.")
						return
					}
					c.String(http.StatusInternalServerError, "Error reading log: "+err.Error())
					return
				}
				c.String(http.StatusOK, string(content))
			})

			api.DELETE("/log", func(c *gin.Context) {
				if err := os.Truncate(LogFile, 0); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to clear log"})
					return
				}
				c.JSON(http.StatusOK, gin.H{"success": true})
			})

			// Health Check API
			api.GET("/health", func(c *gin.Context) {
				status := "stopped"
				if runner.IsRunning() {
					status = "running"
				}
				c.JSON(http.StatusOK, gin.H{"status": status})
			})

			// Service Health Check API
			api.POST("/service-health", func(c *gin.Context) {
				// Parse request body containing list of services to check
				var req struct {
					Services []struct {
						Hostname string `json:"hostname"`
						Service  string `json:"service"`
					} `json:"services"`
				}

				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request format"})
					return
				}

				tunnelRunning := runner.IsRunning()
				var healthChecks []map[string]interface{}

				// Check each service
				for _, svc := range req.Services {
					hostname := svc.Hostname
					service := svc.Service

					// Check origin service health
					originStatus := "offline"
					originResponseTime := 0

					// Parse service URL for health check
					serviceURL := service

					// Handle different protocols for health checks
					switch {
					case strings.HasPrefix(serviceURL, "http://"):
						fallthrough
					case strings.HasPrefix(serviceURL, "https://"):
						// HTTP/HTTPS - extract host:port and try TCP connection
						conn, err := net.DialTimeout("tcp", extractHostPort(serviceURL), 3*time.Second)
						if err == nil {
							conn.Close()
							originStatus = "online"
							originResponseTime = 0
						}

					case strings.HasPrefix(serviceURL, "tcp://"):
						// TCP - extract host:port and try TCP connection
						conn, err := net.DialTimeout("tcp", extractHostPort(serviceURL), 3*time.Second)
						if err == nil {
							conn.Close()
							originStatus = "online"
							originResponseTime = 0
						}

					case strings.HasPrefix(serviceURL, "udp://"):
						// UDP - health checks are not reliable for UDP, just mark as configured
						originStatus = "configured"
						originResponseTime = 0

					case strings.HasPrefix(serviceURL, "ssh://"):
						// SSH - extract host:port and try TCP connection (SSH uses TCP)
						conn, err := net.DialTimeout("tcp", extractHostPort(serviceURL), 3*time.Second)
						if err == nil {
							conn.Close()
							originStatus = "online"
							originResponseTime = 0
						}

					case strings.HasPrefix(serviceURL, "smb://"):
						// SMB - extract host:port and try TCP connection (SMB uses TCP, usually port 445)
						conn, err := net.DialTimeout("tcp", extractHostPort(serviceURL), 3*time.Second)
						if err == nil {
							conn.Close()
							originStatus = "online"
							originResponseTime = 0
						}

					case strings.HasPrefix(serviceURL, "rdp://"):
						// RDP - extract host:port and try TCP connection (RDP uses TCP, usually port 3389)
						conn, err := net.DialTimeout("tcp", extractHostPort(serviceURL), 3*time.Second)
						if err == nil {
							conn.Close()
							originStatus = "online"
							originResponseTime = 0
						}

					default:
						// Unknown protocol - try HTTP as fallback for backward compatibility
						conn, err := net.DialTimeout("tcp", extractHostPort("http://"+service), 3*time.Second)
						if err == nil {
							conn.Close()
							originStatus = "online"
							originResponseTime = 0
						}
					}

					// Check tunnel health (if tunnel is running and service is accessible)
					tunnelStatus := "offline"
					if tunnelRunning && originStatus == "online" {
						// Try to check if the service is accessible through the tunnel
						conn, err := net.DialTimeout("tcp", hostname+":443", 3*time.Second)
						if err == nil {
							conn.Close()
							tunnelStatus = "online"
						} else {
							// Try HTTP as well
							conn, err = net.DialTimeout("tcp", hostname+":80", 3*time.Second)
							if err == nil {
								conn.Close()
								tunnelStatus = "online"
							}
						}
					}

					healthChecks = append(healthChecks, map[string]interface{}{
						"hostname":       hostname,
						"origin_status":  originStatus,
						"tunnel_status":  tunnelStatus,
						"response_time":  originResponseTime,
					})
				}

				c.JSON(http.StatusOK, gin.H{
					"success":       true,
					"tunnel_running": tunnelRunning,
					"health_checks": healthChecks,
				})
			})



			// Get Tunnels API
			api.GET("/tunnels", func(c *gin.Context) {
				cfg, err := config.GetAppConfig()
				if err != nil {
					c.JSON(http.StatusOK, gin.H{
						"success": true,
						"result": []any{},
					})
					return
				}

				// Get all tunnels for this account
				tunnelsRes, status, err := cloudflare.Request("GET", fmt.Sprintf("/accounts/%s/tunnels?is_deleted=false", cfg.AccountID), cfg.APIToken, nil)
				if err != nil || status != 200 {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to get tunnels"})
					return
				}

				resultList, ok := tunnelsRes["result"].([]any)
				if !ok {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Invalid tunnels response"})
					return
				}

				c.JSON(http.StatusOK, gin.H{
					"success": true,
					"result": resultList,
				})
			})

			api.POST("/verify-token", func(c *gin.Context) {
				var req struct{ Token string `json:"token"` }
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}

				// 1. Basic token verification
				_, status, err := cloudflare.Request("GET", "/user/tokens/verify", req.Token, nil)
				if err != nil || status != 200 {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid API token"})
					return
				}

				// 2. Get account information
				accsRes, _, err := cloudflare.Request("GET", "/accounts", req.Token, nil)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Failed to access account: " + err.Error()})
					return
				}
				resultList, ok := accsRes["result"].([]interface{})
				if !ok || len(resultList) == 0 {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "No accounts found"})
					return
				}
				firstAcc := resultList[0].(map[string]interface{})
				accountID := firstAcc["id"].(string)

				// 3. Verify DNS access - try to list zones
				_, zonesStatus, err := cloudflare.Request("GET", "/zones?per_page=1", req.Token, nil)
				if err != nil || zonesStatus != 200 {
					fmt.Printf("[Verify] DNS access check failed: status=%d, error=%v\n", zonesStatus, err)
					c.JSON(http.StatusBadRequest, gin.H{
						"success": false,
						"error": "Insufficient permissions: API token requires 'Zone:Zone:Read' and 'Zone:DNS:Edit' permissions",
					})
					return
				}

				// 4. Verify Tunnel access - try to list tunnels
				tunnelsRes, tunnelsStatus, err := cloudflare.Request("GET", fmt.Sprintf("/accounts/%s/tunnels?is_deleted=false", accountID), req.Token, nil)
				if err != nil || tunnelsStatus != 200 {
					fmt.Printf("[Verify] Tunnel access check failed: status=%d, error=%v\n", tunnelsStatus, err)
					c.JSON(http.StatusBadRequest, gin.H{
						"success": false,
						"error": "Insufficient permissions: API token requires 'Account:Cloudflare Tunnel:Edit' permission",
					})
					return
				}

				fmt.Printf("[Verify] Token verification successful for account %s\n", accountID)

				c.JSON(http.StatusOK, gin.H{
					"success":    true,
					"account_id": accountID,
					"tunnels":    tunnelsRes["result"],
				})
			})

			api.PUT("/config/tunnel", func(c *gin.Context) {
				var req struct {
					TunnelID   string `json:"tunnel_id"`
					TunnelName string `json:"tunnel_name"`
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}

				cfg, _ := config.GetAppConfig()
				if cfg == nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Not configured"})
					return
				}

				// Fetch new token immediately
				token, err := cloudflare.GetTunnelToken(cfg.AccountID, req.TunnelID, cfg.APIToken)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to fetch tunnel token: " + err.Error()})
					return
				}

				cfg.TunnelID = req.TunnelID
				cfg.TunnelName = req.TunnelName
				cfg.TunnelToken = token

				if err := config.SaveAppConfig(cfg); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to save config"})
					return
				}

				go func() {
					if err := runner.Restart(cfg); err != nil {
						fmt.Printf("[Update] Failed to restart tunnel: %v\n", err)
					}
				}()

				c.JSON(http.StatusOK, gin.H{"success": true})
			})

			api.POST("/save-config", func(c *gin.Context) {
				var req config.Config
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}

				// Fetch token immediately (Monolithic logic did this)
				token, err := cloudflare.GetTunnelToken(req.AccountID, req.TunnelID, req.APIToken)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to fetch tunnel token: " + err.Error()})
					return
				}
				req.TunnelToken = token

				if err := config.SaveAppConfig(&req); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
					return
				}

				go func() {
					if err := runner.Restart(&req); err != nil {
						fmt.Printf("[Setup] Failed to start tunnel: %v\n", err)
					}
				}()

				c.JSON(http.StatusOK, gin.H{"success": true})
			})

			api.GET("/config", func(c *gin.Context) {
				cfg, err := config.GetAppConfig()
				if err != nil || cfg == nil {
					c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Not configured"})
					return
				}

				url := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/configurations", cfg.AccountID, cfg.TunnelID)
				res, _, err := cloudflare.Request("GET", url, cfg.APIToken, nil)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}

				if success, ok := res["success"].(bool); !ok || !success {
					c.JSON(http.StatusBadRequest, res)
					return
				}

				var visibleIngress []interface{}
				resultObj, _ := res["result"].(map[string]interface{})
				configObj, _ := resultObj["config"].(map[string]interface{})
				ingressList, _ := configObj["ingress"].([]interface{})

				for _, item := range ingressList {
					r, ok := item.(map[string]interface{})
					if ok && r["hostname"] != nil {
						visibleIngress = append(visibleIngress, r)
					}
				}

				c.JSON(http.StatusOK, gin.H{
					"success":     true,
					"tunnel_name": cfg.TunnelName,
					"ingress":     visibleIngress,
				})
			})
			
			api.GET("/zones", func(c *gin.Context) {
				cfg, _ := config.GetAppConfig()
				if cfg == nil {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "Not configured"})
					return
				}
				res, _, err := cloudflare.Request("GET", "/zones?status=active", cfg.APIToken, nil)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, res)
			})

			// Docker containers endpoint
			api.GET("/containers", func(c *gin.Context) {
				// Use docker command directly to list containers
				cmd := exec.Command("docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}")
				output, err := cmd.Output()
				if err != nil {
					c.JSON(http.StatusServiceUnavailable, gin.H{
						"success": false,
						"error": "Docker is not available or not accessible",
						"containers": []interface{}{},
					})
					return
				}

				// Parse the output
				lines := strings.Split(strings.TrimSpace(string(output)), "\n")
				if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
					c.JSON(http.StatusOK, gin.H{
						"success": true,
						"containers": []interface{}{},
					})
					return
				}

				var containerList []gin.H
				for _, line := range lines {
					if strings.TrimSpace(line) == "" {
						continue
					}

					// Split by tab
					parts := strings.Split(line, "\t")
					if len(parts) < 4 {
						continue
					}

					id := parts[0]
					if len(id) > 12 {
						id = id[:12] // Short ID
					}

					name := parts[1]
					status := parts[2]
					image := parts[3]
					ports := ""
					if len(parts) > 4 {
						ports = parts[4]
					}

					// Parse ports to extract exposed ports
					var exposedPorts []string
					if ports != "" && ports != "<nil>" {
						portList := strings.Split(ports, ",")
						for _, port := range portList {
							// Extract port number from format like "8080/tcp->0.0.0.0:8080"
							parts := strings.Split(strings.TrimSpace(port), "->")
							if len(parts) > 0 {
								containerPort := strings.TrimSpace(parts[0])
								if containerPort != "" && !strings.Contains(containerPort, "->") {
									exposedPorts = append(exposedPorts, containerPort)
								}
							}
						}
					}

					// Get hostname using docker inspect
					hostname := name
					inspectCmd := exec.Command("docker", "inspect", "--format", "{{.Config.Hostname}}", name)
					if hostnameOutput, err := inspectCmd.Output(); err == nil {
						hn := strings.TrimSpace(string(hostnameOutput))
						if hn != "" && hn != "<no value>" {
							hostname = hn
						}
					}

					containerList = append(containerList, gin.H{
						"id":       id,
						"name":     name,
						"status":   status,
						"image":    image,
						"ports":    exposedPorts,
						"hostname": hostname,
					})
				}

				// Concurrently check health for all containers
				type HealthResult struct {
					Index  int
					Status string
					Detail string
				}
				healthResults := make(chan HealthResult, len(containerList))
				var wg sync.WaitGroup

				for i, container := range containerList {
					wg.Add(1)
					go func(idx int, c gin.H) {
						defer wg.Done()
						hostname, ok := c["hostname"].(string)
						if !ok || hostname == "" {
							healthResults <- HealthResult{Index: idx, Status: "unknown", Detail: "No hostname"}
							return
						}

						// Check Reachability (Ping)
						// Using short timeout (1s) to not delay the list too much
						cmd := exec.Command("ping", "-c", "1", "-W", "1", hostname)
						if err := cmd.Run(); err == nil {
							healthResults <- HealthResult{Index: idx, Status: "reachable", Detail: "Ping Success"}
							return
						}

						// Fallback: Check DNS
						if _, err := net.LookupHost(hostname); err == nil {
							healthResults <- HealthResult{Index: idx, Status: "dns_resolved", Detail: "DNS OK, Ping Failed"}
							return
						}

						healthResults <- HealthResult{Index: idx, Status: "unreachable", Detail: "Resolution Failed"}
					}(i, container)
				}

				// Close channel when all done
				go func() {
					wg.Wait()
					close(healthResults)
				}()

				// Collect results (map index -> health)
				healthMap := make(map[int]HealthResult)
				for res := range healthResults {
					healthMap[res.Index] = res
				}

				// Apply results to container list
				for i := range containerList {
					if res, ok := healthMap[i]; ok {
						containerList[i]["health_status"] = res.Status
						containerList[i]["health_detail"] = res.Detail
					} else {
						containerList[i]["health_status"] = "unknown"
					}
				}

				c.JSON(http.StatusOK, gin.H{
					"success":    true,
					"containers": containerList,
				})
			})



			api.POST("/hostname", func(c *gin.Context) {
				var req struct {
					Hostname string `json:"hostname"`
					Service  string `json:"service"`
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}
				cfg, _ := config.GetAppConfig()
				if cfg == nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Not configured"})
					return
				}

				fmt.Printf("[Debug] Adding hostname: %s -> %s\n", req.Hostname, req.Service)

				// 1. Resolve Zone
				parts := strings.Split(req.Hostname, ".")
				var domain string
				if len(parts) >= 2 {
					domain = strings.Join(parts[len(parts)-2:], ".")
				} else {
					domain = req.Hostname
				}

				findZone := func(d string) (string, error) {
					res, _, err := cloudflare.Request("GET", "/zones?name="+d, cfg.APIToken, nil)
					if err != nil {
						return "", err
					}
					results, _ := res["result"].([]interface{})
					if len(results) > 0 {
						first := results[0].(map[string]interface{})
						return first["id"].(string), nil
					}
					return "", nil
				}

				zoneID, _ := findZone(domain)
				if zoneID == "" {
					zoneID, _ = findZone(req.Hostname)
				}
				if zoneID == "" && len(parts) > 2 {
					domain = strings.Join(parts[len(parts)-3:], ".")
					zoneID, _ = findZone(domain)
				}
				if zoneID == "" {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Could not find Cloudflare Zone"})
					return
				}

				// 2. CHECK DNS Existence
				checkRes, _, err := cloudflare.Request("GET", fmt.Sprintf("/zones/%s/dns_records?name=%s", zoneID, req.Hostname), cfg.APIToken, nil)
				if err == nil {
					if valid, ok := checkRes["success"].(bool); ok && valid {
						records, _ := checkRes["result"].([]interface{})
						if len(records) > 0 {
							// Return detailed conflict info
							rec := records[0].(map[string]interface{})
							c.JSON(http.StatusConflict, gin.H{
								"success": false,
								"error":   "DNS Record Exists",
								"record": map[string]interface{}{
									"id":      rec["id"],
									"type":    rec["type"],
									"name":    rec["name"],
									"content": rec["content"],
								},
							})
							return
						}
					}
				}

				// 3. Create DNS
				dnsBody := map[string]interface{}{
					"type":    "CNAME",
					"name":    req.Hostname,
					"content": fmt.Sprintf("%s.cfargotunnel.com", cfg.TunnelID),
					"proxied": true,
					"comment": "Managed by FlareGate",
				}
				dnsRes, code, err := cloudflare.Request("POST", fmt.Sprintf("/zones/%s/dns_records", zoneID), cfg.APIToken, dnsBody)
				if err != nil {
					c.JSON(code, gin.H{"success": false, "error": err.Error()})
					return
				}
				if s, ok := dnsRes["success"].(bool); !ok || !s {
					errs, _ := dnsRes["errors"].([]interface{})
					msg := "Unknown error"
					if len(errs) > 0 {
						if eMap, ok := errs[0].(map[string]interface{}); ok {
							msg = fmt.Sprintf("%v", eMap["message"])
						}
					}
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msg})
					return
				}

				// 4. Update Config (Ingress)
				confUrl := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/configurations", cfg.AccountID, cfg.TunnelID)
				confRes, _, err := cloudflare.Request("GET", confUrl, cfg.APIToken, nil)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to fetch tunnel config: " + err.Error()})
					return
				}

				var ingress []interface{}
				if rObj, ok := confRes["result"].(map[string]interface{}); ok {
					if cObj, ok := rObj["config"].(map[string]interface{}); ok {
						if iList, ok := cObj["ingress"].([]interface{}); ok {
							ingress = iList
						}
					}
				}

				// Check if hostname already exists in ingress
				for _, rule := range ingress {
					if m, ok := rule.(map[string]interface{}); ok {
						if hostname, exists := m["hostname"]; exists && hostname == req.Hostname {
							c.JSON(http.StatusConflict, gin.H{"success": false, "error": "Hostname already exists in tunnel configuration"})
							return
						}
					}
				}

				newRule := map[string]interface{}{
					"hostname": req.Hostname,
					"service":  req.Service,
					"originRequest": map[string]interface{}{
						"noTLSVerify": true,
					},
				}

				fmt.Printf("[Debug] Adding new ingress rule: %+v\n", newRule)

				// Find the catch-all rule (rule without hostname) and insert before it
				var newIngress []interface{}
				catchAllFound := false

				for _, rule := range ingress {
					if m, ok := rule.(map[string]interface{}); ok {
						if _, hasHostname := m["hostname"]; !hasHostname && !catchAllFound {
							// This is the catch-all rule, insert new rule before it
							newIngress = append(newIngress, newRule)
							newIngress = append(newIngress, rule)
							catchAllFound = true
							fmt.Printf("[Debug] Inserted new rule before catch-all\n")
						} else {
							// Regular rule or catch-all (if already found)
							newIngress = append(newIngress, rule)
						}
					} else {
						newIngress = append(newIngress, rule)
					}
				}

				// If no catch-all rule found, add the new rule at the beginning
				if !catchAllFound {
					newIngress = append([]interface{}{newRule}, newIngress...)
					fmt.Printf("[Debug] No catch-all rule found, adding new rule at beginning\n")
				}

				fmt.Printf("[Debug] Total ingress rules count: %d\n", len(newIngress))

				// Save Config
				updateBody := map[string]interface{}{
					"config": map[string]interface{}{
						"ingress": newIngress,
					},
				}
				
				saveRes, code, err := cloudflare.Request("PUT", confUrl, cfg.APIToken, updateBody)
				if err != nil {
					fmt.Printf("[Error] Tunnel config update failed: %v\n", err)
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to update tunnel config: " + err.Error()})
					return
				}
				if code != 200 {
					fmt.Printf("[Error] Tunnel config update failed with status %d: %+v\n", code, saveRes)
					c.JSON(code, gin.H{"success": false, "error": "Failed to update tunnel config"})
					return
				}
				if s, ok := saveRes["success"].(bool); !ok || !s {
					fmt.Printf("[Error] Cloudflare rejected config update: %+v\n", saveRes)
					errMsg := "Cloudflare rejected config update"
					if errs, ok := saveRes["errors"].([]interface{}); ok && len(errs) > 0 {
						if eMap, ok := errs[0].(map[string]interface{}); ok {
							if msg, ok := eMap["message"].(string); ok {
								errMsg = msg
							}
						}
					}
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": errMsg})
					return
				}

				// Trigger Restart
				go func() {
					runner.Restart(cfg)
				}()

				c.JSON(http.StatusOK, gin.H{"success": true})
			})

			api.DELETE("/dns", func(c *gin.Context) {
				var req struct {
					RecordID string `json:"record_id"`
					Hostname string `json:"hostname"` 
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}
				cfg, _ := config.GetAppConfig()
				if cfg == nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Not configured"})
					return
				}

				parts := strings.Split(req.Hostname, ".")
				var domain string
				if len(parts) >= 2 {
					domain = strings.Join(parts[len(parts)-2:], ".")
				} else {
					domain = req.Hostname
				}
				findZone := func(d string) (string, error) {
					res, _, err := cloudflare.Request("GET", "/zones?name="+d, cfg.APIToken, nil)
					if err != nil { return "", err }
					results, _ := res["result"].([]interface{})
					if len(results) > 0 {
						return results[0].(map[string]interface{})["id"].(string), nil
					}
					return "", nil
				}
				zoneID, _ := findZone(domain)
				if zoneID == "" {
					zoneID, _ = findZone(req.Hostname)
				}
				if zoneID == "" && len(parts) > 2 {
					domain = strings.Join(parts[len(parts)-3:], ".")
					zoneID, _ = findZone(domain)
				}

				if zoneID == "" {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Could not find Zone for hostname"})
					return
				}

				_, code, err := cloudflare.Request("DELETE", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, req.RecordID), cfg.APIToken, nil)
				if err != nil {
					c.JSON(code, gin.H{"success": false, "error": err.Error()})
					return
				}
				
				c.JSON(http.StatusOK, gin.H{"success": true})
			})

			api.PUT("/hostname", func(c *gin.Context) {
				var req struct {
					Hostname string `json:"hostname"`
					Service  string `json:"service"`
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return 
				}
				cfg, _ := config.GetAppConfig()
				confUrl := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/configurations", cfg.AccountID, cfg.TunnelID)
				confRes, _, _ := cloudflare.Request("GET", confUrl, cfg.APIToken, nil)
				
				var ingress []interface{}
				if rObj, ok := confRes["result"].(map[string]interface{}); ok {
					if cObj, ok := rObj["config"].(map[string]interface{}); ok {
						ingress = cObj["ingress"].([]interface{})
					}
				}

				updated := false
				for i, rule := range ingress {
					m := rule.(map[string]interface{})
					if m["hostname"] == req.Hostname {
						m["service"] = req.Service
						ingress[i] = m
						updated = true
						break
					}
				}
				if !updated {
					c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Hostname not found"})
					return
				}
				updateBody := map[string]interface{}{ "config": map[string]interface{}{ "ingress": ingress } }
				cloudflare.Request("PUT", confUrl, cfg.APIToken, updateBody)
				go func() { runner.Restart(cfg) }()
				c.JSON(http.StatusOK, gin.H{"success": true})
			})

			api.DELETE("/hostname", func(c *gin.Context) {
				var req struct {
					Hostname string `json:"hostname"`
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}
				cfg, _ := config.GetAppConfig()
				confUrl := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/configurations", cfg.AccountID, cfg.TunnelID)
				confRes, _, _ := cloudflare.Request("GET", confUrl, cfg.APIToken, nil)
				
				var ingress []interface{}
				if rObj, ok := confRes["result"].(map[string]interface{}); ok {
					if cObj, ok := rObj["config"].(map[string]interface{}); ok {
						ingress = cObj["ingress"].([]interface{})
					}
				}

				var newIngress []interface{}
				for _, rule := range ingress {
					m := rule.(map[string]interface{})
					if m["hostname"] != req.Hostname {
						newIngress = append(newIngress, rule)
					}
				}

				if len(newIngress) == len(ingress) {
					c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Hostname not found"})
					return
				}
				updateBody := map[string]interface{}{ "config": map[string]interface{}{ "ingress": newIngress } }
				cloudflare.Request("PUT", confUrl, cfg.APIToken, updateBody)

				// 2. Delete DNS (Best effort)
				parts := strings.Split(req.Hostname, ".")
				var domain string
				if len(parts) >= 2 { domain = strings.Join(parts[len(parts)-2:], ".") } else { domain = req.Hostname }
				
				res, _, _ := cloudflare.Request("GET", "/zones?name="+domain, cfg.APIToken, nil)
				if r, ok := res["result"].([]interface{}); ok && len(r) > 0 {
					zoneID := r[0].(map[string]interface{})["id"].(string)
					dRes, _, _ := cloudflare.Request("GET", fmt.Sprintf("/zones/%s/dns_records?name=%s", zoneID, req.Hostname), cfg.APIToken, nil)
					if dr, ok := dRes["result"].([]interface{}); ok && len(dr) > 0 {
						recID := dr[0].(map[string]interface{})["id"].(string)
						cloudflare.Request("DELETE", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recID), cfg.APIToken, nil)
					}
				}

				go func() { runner.Restart(cfg) }()
				c.JSON(http.StatusOK, gin.H{"success": true})
			})

			// System Hostname Handler
			api.POST("/system-hostname", func(c *gin.Context) {
				var req struct {
					Hostname string `json:"hostname"`
					Service  string `json:"service"`
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}
				cfg, _ := config.GetAppConfig()
				if cfg == nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Not configured"})
					return
				}

				// Check if system hostname already exists
				if cfg.SystemHostname != "" {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "System hostname already configured"})
					return
				}

				// Get current port from environment
				port := os.Getenv("PORT")
				if port == "" {
					port = "8020"
				}

				// Force service to use current port
				req.Service = fmt.Sprintf("http://localhost:%s", port)

				// 1. Resolve Zone
				parts := strings.Split(req.Hostname, ".")
				var domain string
				if len(parts) >= 2 {
					domain = strings.Join(parts[len(parts)-2:], ".")
				} else {
					domain = req.Hostname
				}

				findZone := func(d string) (string, error) {
					res, _, err := cloudflare.Request("GET", "/zones?name="+d, cfg.APIToken, nil)
					if err != nil {
						return "", err
					}
					results, _ := res["result"].([]interface{})
					if len(results) > 0 {
						first := results[0].(map[string]interface{})
						return first["id"].(string), nil
					}
					return "", nil
				}

				zoneID, _ := findZone(domain)
				if zoneID == "" {
					zoneID, _ = findZone(req.Hostname)
				}
				if zoneID == "" && len(parts) > 2 {
					domain = strings.Join(parts[len(parts)-3:], ".")
					zoneID, _ = findZone(domain)
				}
				if zoneID == "" {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Could not find Cloudflare Zone"})
					return
				}

				// 2. CHECK DNS Existence
				checkRes, _, err := cloudflare.Request("GET", fmt.Sprintf("/zones/%s/dns_records?name=%s", zoneID, req.Hostname), cfg.APIToken, nil)
				if err == nil {
					if valid, ok := checkRes["success"].(bool); ok && valid {
						records, _ := checkRes["result"].([]interface{})
						if len(records) > 0 {
							// Return detailed conflict info
							rec := records[0].(map[string]interface{})
							c.JSON(http.StatusConflict, gin.H{
								"success": false,
								"error":   "DNS Record Exists",
								"record": map[string]interface{}{
									"id":      rec["id"],
									"type":    rec["type"],
									"name":    rec["name"],
									"content": rec["content"],
								},
							})
							return
						}
					}
				}

				// 3. Create DNS
				dnsBody := map[string]interface{}{
					"type":    "CNAME",
					"name":    req.Hostname,
					"content": fmt.Sprintf("%s.cfargotunnel.com", cfg.TunnelID),
					"proxied": true,
					"comment": "System hostname - Managed by Tunnel Local GUI",
				}
				dnsRes, code, err := cloudflare.Request("POST", fmt.Sprintf("/zones/%s/dns_records", zoneID), cfg.APIToken, dnsBody)
				if err != nil {
					c.JSON(code, gin.H{"success": false, "error": err.Error()})
					return
				}
				if s, ok := dnsRes["success"].(bool); !ok || !s {
					errs, _ := dnsRes["errors"].([]interface{})
					msg := "Unknown error"
					if len(errs) > 0 {
						if eMap, ok := errs[0].(map[string]interface{}); ok {
							msg = fmt.Sprintf("%v", eMap["message"])
						}
					}
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msg})
					return
				}

				// 4. Update Config (Ingress)
				confUrl := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/configurations", cfg.AccountID, cfg.TunnelID)
				confRes, _, err := cloudflare.Request("GET", confUrl, cfg.APIToken, nil)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to fetch tunnel config: " + err.Error()})
					return
				}

				var ingress []interface{}
				if rObj, ok := confRes["result"].(map[string]interface{}); ok {
					if cObj, ok := rObj["config"].(map[string]interface{}); ok {
						if iList, ok := cObj["ingress"].([]interface{}); ok {
							ingress = iList
						}
					}
				}

				newRule := map[string]interface{}{
					"hostname": req.Hostname,
					"service":  req.Service,
					"originRequest": map[string]interface{}{
						"noTLSVerify": true,
					},
				}

				// Find the catch-all rule (rule without hostname) and insert before it
				var newIngress []interface{}
				catchAllFound := false

				for _, rule := range ingress {
					if m, ok := rule.(map[string]interface{}); ok {
						if _, hasHostname := m["hostname"]; !hasHostname && !catchAllFound {
							// This is the catch-all rule, insert new rule before it
							newIngress = append(newIngress, newRule)
							newIngress = append(newIngress, rule)
							catchAllFound = true
						} else {
							// Regular rule or catch-all (if already found)
							newIngress = append(newIngress, rule)
						}
					} else {
						newIngress = append(newIngress, rule)
					}
				}

				// If no catch-all rule found, add the new rule at the beginning
				if !catchAllFound {
					newIngress = append([]interface{}{newRule}, newIngress...)
				}

				updateBody := map[string]interface{}{"config": map[string]interface{}{"ingress": newIngress}}
				_, _, err = cloudflare.Request("PUT", confUrl, cfg.APIToken, updateBody)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to update tunnel config: " + err.Error()})
					return
				}

				// 5. Save system hostname to config
				cfg.SystemHostname = req.Hostname
				if err := config.SaveAppConfig(cfg); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to save system hostname: " + err.Error()})
					return
				}

				// 6. Restart tunnel
				go func() { runner.Restart(cfg) }()

				c.JSON(http.StatusOK, gin.H{
					"success": true,
					"hostname": req.Hostname,
					"service": req.Service,
				})
			})

			// Get System Hostname API
			api.GET("/system-hostname", func(c *gin.Context) {
				cfg, err := config.GetAppConfig()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{
					"success": true,
					"systemHostname": cfg.SystemHostname,
				})
			})

			// Update System Hostname API
			api.PUT("/system-hostname-update", func(c *gin.Context) {
				var req struct {
					Hostname string `json:"hostname"`
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}

				cfg, err := config.GetAppConfig()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
					return
				}

				// Update system hostname
				cfg.SystemHostname = req.Hostname
				if err := config.SaveAppConfig(cfg); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
					return
				}

				c.JSON(http.StatusOK, gin.H{"success": true})
			})

			// Reset Configuration API (for changing API token)
			api.DELETE("/config", func(c *gin.Context) {
				cfg, err := config.GetAppConfig()
				if err != nil || cfg == nil {
					c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "No configuration found"})
					return
				}

				// Stop the running tunnel
				go func() {
					if runner.IsRunning() {
						if err := runner.Stop(); err != nil {
							fmt.Printf("[Reset] Failed to stop tunnel: %v\n", err)
						}
					}
				}()

				// Delete the configuration from database
				if err := config.DeleteAppConfig(); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to delete configuration: " + err.Error()})
					return
				}

				fmt.Printf("[Reset] Configuration deleted successfully\n")
				c.JSON(http.StatusOK, gin.H{"success": true, "message": "Configuration reset successfully"})
			})
		}
	}

	fmt.Printf("\n🚀 Server is running at: http://localhost:%s\n", port)

	if err := r.Run(":" + port); err != nil {
		if strings.Contains(err.Error(), "bind: address already in use") {
			fmt.Printf("\n[ERROR] Port %s is already in use.\n", port)
			fmt.Println("To kill the process using this port, run:")
			fmt.Printf("  fuser -k %s/tcp\n", port)
			os.Exit(1)
		}
		log.Fatal(err)
	}
}

// Helper function to extract host and port from URL
func extractHostPort(serviceURL string) string {
	// Remove protocol prefix
	var hostPort string
	switch {
	case strings.HasPrefix(serviceURL, "http://"):
		hostPort = strings.TrimPrefix(serviceURL, "http://")
	case strings.HasPrefix(serviceURL, "https://"):
		hostPort = strings.TrimPrefix(serviceURL, "https://")
	case strings.HasPrefix(serviceURL, "tcp://"):
		hostPort = strings.TrimPrefix(serviceURL, "tcp://")
	case strings.HasPrefix(serviceURL, "udp://"):
		hostPort = strings.TrimPrefix(serviceURL, "udp://")
	case strings.HasPrefix(serviceURL, "ssh://"):
		hostPort = strings.TrimPrefix(serviceURL, "ssh://")
	case strings.HasPrefix(serviceURL, "smb://"):
		hostPort = strings.TrimPrefix(serviceURL, "smb://")
	case strings.HasPrefix(serviceURL, "rdp://"):
		hostPort = strings.TrimPrefix(serviceURL, "rdp://")
	default:
		hostPort = serviceURL
	}

	// Extract host:port part (remove path if present)
	if idx := strings.Index(hostPort, "/"); idx != -1 {
		hostPort = hostPort[:idx]
	}

	// Default to port 80 if not specified (for HTTP protocols)
	if !strings.Contains(hostPort, ":") {
		// Use appropriate default ports for different protocols
		if strings.HasPrefix(serviceURL, "https://") {
			hostPort = hostPort + ":443"
		} else if strings.HasPrefix(serviceURL, "ssh://") {
			hostPort = hostPort + ":22"
		} else if strings.HasPrefix(serviceURL, "smb://") {
			hostPort = hostPort + ":445"
		} else if strings.HasPrefix(serviceURL, "rdp://") {
			hostPort = hostPort + ":3389"
		} else {
			hostPort = hostPort + ":80"
		}
	}

	return hostPort
}

// Helper function to get keys from a map for debugging
func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func getOrCreateSecretKey() string {
	// 1. Check Env
	if key := os.Getenv("SECRET_KEY"); key != "" {
		log.Printf("[Init] Using SECRET_KEY from environment")
		return key
	}

	// 2. Check File
	// Ensure data directory exists
	if err := os.MkdirAll("data", 0755); err != nil {
		log.Printf("[Init] Warning: Failed to create data directory: %v", err)
	}

	keyPath := filepath.Join("data", "secret.key")
	if content, err := os.ReadFile(keyPath); err == nil {
		key := strings.TrimSpace(string(content))
		log.Printf("[Init] Using existing SECRET_KEY from %s", keyPath)
		return key
	}

	// 3. Generate
	key, err := generateRandomString(32)
	if err != nil {
		log.Printf("[Init] Warning: Failed to generate random key: %v", err)
		log.Printf("[Init] Using default insecure key - please set SECRET_KEY environment variable!")
		return "default-insecure-secret-key"
	}

	// 4. Save
	if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
		log.Printf("[Init] Warning: Failed to save secret key: %v", err)
	} else {
		log.Printf("[Init] Generated and saved new SECRET_KEY to %s", keyPath)
	}

	return key
}

func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

