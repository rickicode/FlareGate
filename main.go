package main

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
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

	"aidanwoods.dev/go-paseto"
	"github.com/gin-gonic/gin"

	"flaregate/internal/cloudflare"
	"flaregate/internal/config"
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
	// CLI mode: if arguments are provided, handle command and exit.
	if len(os.Args) > 1 {
		config.InitDB()
		runCLI()
		return
	}

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
	_, err := getOrCreateSecretKey()
	if err != nil {
		log.Fatalf("[Init] Failed to initialize SECRET_KEY: %v", err)
	}

	// Secret key is now stored in data/secret.key; used by config encryption.

	// Initialize PASETO v4 symmetric key for auth tokens.
	// Regenerated on restart — existing tokens become invalid, users must re-login.
	pasetoKey = paseto.NewV4SymmetricKey()

	// Print login information
	printLoginInfo(port)

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
		token, err := c.Cookie("paseto_token")
		if err != nil {
			token = strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		}
		if token == "" {
			if c.Request.Header.Get("X-Requested-With") == "XMLHttpRequest" || strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			} else {
				c.Redirect(http.StatusFound, "/login")
			}
			c.Abort()
			return
		}

		userID, username, err := validatePASETOToken(token)
		if err != nil {
			c.SetCookie("paseto_token", "", -1, "/", "", false, true)
			if c.Request.Header.Get("X-Requested-With") == "XMLHttpRequest" || strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token expired or invalid"})
			} else {
				c.Redirect(http.StatusFound, "/login")
			}
			c.Abort()
			return
		}

		c.Set("user_id", userID)
		c.Set("username", username)
		c.Next()
	}

	// Login Routes
	r.GET("/login", func(c *gin.Context) {
		if _, err := c.Cookie("paseto_token"); err == nil {
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

		token, err := createPASETOToken(user.ID, user.Username)
		if err != nil {
			log.Printf("[Login] Error creating token: %v", err)
			c.HTML(http.StatusOK, "login.html", gin.H{"error": "Failed to create session"})
			return
		}

		// HttpOnly cookie valid for 7 days, Secure=false for local HTTP access.
		c.SetCookie("paseto_token", token, 86400*7, "/", "", false, true)

		log.Printf("[Login] Success: username=%s", user.Username)

		c.Redirect(http.StatusFound, "/")
	})

	r.GET("/logout", func(c *gin.Context) {
		c.SetCookie("paseto_token", "", -1, "/", "", false, true)
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
				"error":    "Passwords do not match",
				"username": username,
			})
			return
		}

		if len(password) < 6 {
			c.HTML(http.StatusOK, "register.html", gin.H{
				"error":    "Password must be at least 6 characters",
				"username": username,
			})
			return
		}

		user, err := config.CreateUser(username, password)
		if err != nil {
			c.HTML(http.StatusOK, "register.html", gin.H{
				"error":    "Failed to create user: " + err.Error(),
				"username": username,
			})
			return
		}

		log.Printf("[Register] Success: created user %s", user.Username)

		token, err := createPASETOToken(user.ID, user.Username)
		if err != nil {
			log.Printf("[Register] Error creating token: %v", err)
			c.HTML(http.StatusOK, "register.html", gin.H{"error": "Account created but session failed"})
			return
		}
		c.SetCookie("paseto_token", token, 86400*7, "/", "", false, true)

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

			visibleIngress, err := loadVisibleIngress(cfg)
			if err != nil {
				log.Printf("[Dashboard] Failed to load ingress: %v", err)
				visibleIngress = []interface{}{}
			}

			c.HTML(http.StatusOK, "index.html", gin.H{
				"Configured":       true,
				"TunnelName":       cfg.TunnelName,
				"Ingress":          visibleIngress,
				"ShowChangeTunnel": true,
				"ActivePage":       "dashboard",
				"SystemHostname":   cfg.SystemHostname,
				"Port":             port,
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
				"TunnelName":       tunnelName,
				"ShowChangeTunnel": false,
				"ActivePage":       "logs",
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
						"hostname":      hostname,
						"origin_status": originStatus,
						"tunnel_status": tunnelStatus,
						"response_time": originResponseTime,
					})
				}

				c.JSON(http.StatusOK, gin.H{
					"success":        true,
					"tunnel_running": tunnelRunning,
					"health_checks":  healthChecks,
				})
			})

			// Get Tunnels API
			api.GET("/tunnels", func(c *gin.Context) {
				cfg, err := config.GetAppConfig()
				if err != nil {
					c.JSON(http.StatusOK, gin.H{
						"success": true,
						"result":  []any{},
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
					"result":  resultList,
				})
			})

			api.POST("/verify-token", func(c *gin.Context) {
				var req struct {
					Token string `json:"token"`
				}
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
						"error":   "Insufficient permissions: API token requires 'Zone:Zone:Read' and 'Zone:DNS:Edit' permissions",
					})
					return
				}

				// 4. Verify Tunnel access - try to list tunnels
				tunnelsRes, tunnelsStatus, err := cloudflare.Request("GET", fmt.Sprintf("/accounts/%s/tunnels?is_deleted=false", accountID), req.Token, nil)
				if err != nil || tunnelsStatus != 200 {
					fmt.Printf("[Verify] Tunnel access check failed: status=%d, error=%v\n", tunnelsStatus, err)
					c.JSON(http.StatusBadRequest, gin.H{
						"success": false,
						"error":   "Insufficient permissions: API token requires 'Account:Cloudflare Tunnel:Edit' permission",
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
				var req struct {
					AccountID  string `json:"account_id"`
					TunnelID   string `json:"tunnel_id"`
					TunnelName string `json:"tunnel_name"`
					APIToken   string `json:"api_token"`
				}
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

				cfgToSave := config.Config{
					AccountID:   req.AccountID,
					TunnelID:    req.TunnelID,
					TunnelName:  req.TunnelName,
					APIToken:    req.APIToken,
					TunnelToken: token,
				}

				if err := config.SaveAppConfig(&cfgToSave); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
					return
				}

				go func() {
					if err := runner.Restart(&cfgToSave); err != nil {
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

				visibleIngress, err := loadVisibleIngress(cfg)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
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
						"success":    false,
						"error":      "Docker is not available or not accessible",
						"containers": []interface{}{},
					})
					return
				}

				// Parse the output
				lines := strings.Split(strings.TrimSpace(string(output)), "\n")
				if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
					c.JSON(http.StatusOK, gin.H{
						"success":    true,
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

				hostname, err := normalizeHostname(req.Hostname)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}
				service, err := normalizeService(req.Service)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}

				cfg, _ := config.GetAppConfig()
				if cfg == nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Not configured"})
					return
				}

				zoneID, _, err := cloudflare.ResolveZoneByHostname(cfg.APIToken, hostname)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}

				if _, err := cloudflare.EnsureTunnelDNSRecord(cfg.APIToken, zoneID, hostname, cfg.TunnelID, "Managed by FlareGate"); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}

				changed, err := mutateTunnelIngress(cfg, func(ingress []interface{}) ([]interface{}, bool, error) {
					return upsertIngressRule(ingress, hostname, service)
				})
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to update tunnel config: " + err.Error()})
					return
				}
				if changed {
					scheduleTunnelRestart(cfg)
				}

				c.JSON(http.StatusOK, gin.H{"success": true, "hostname": hostname, "service": service})
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

				hostname, err := normalizeHostname(req.Hostname)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}
				if strings.TrimSpace(req.RecordID) == "" {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "record_id is required"})
					return
				}

				zoneID, _, err := cloudflare.ResolveZoneByHostname(cfg.APIToken, hostname)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}

				if err := cloudflare.DeleteDNSRecord(cfg.APIToken, zoneID, strings.TrimSpace(req.RecordID)); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
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

				hostname, err := normalizeHostname(req.Hostname)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}
				service, err := normalizeService(req.Service)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}
				cfg, _ := config.GetAppConfig()
				if cfg == nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Not configured"})
					return
				}

				found := false
				changed, err := mutateTunnelIngress(cfg, func(ingress []interface{}) ([]interface{}, bool, error) {
					var ruleChanged bool
					var updateErr error
					ingress, found, ruleChanged, updateErr = updateExistingIngressRule(ingress, hostname, service)
					return ingress, ruleChanged, updateErr
				})
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
					return
				}
				if !found {
					c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Hostname not found"})
					return
				}
				if changed {
					scheduleTunnelRestart(cfg)
				}
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
				hostname, err := normalizeHostname(req.Hostname)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}
				cfg, _ := config.GetAppConfig()
				if cfg == nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Not configured"})
					return
				}

				found := false
				changed := false
				changed, err = mutateTunnelIngress(cfg, func(ingress []interface{}) ([]interface{}, bool, error) {
					var removeErr error
					ingress, found, changed, removeErr = removeIngressRule(ingress, hostname)
					return ingress, changed, removeErr
				})
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
					return
				}
				if !found {
					c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Hostname not found"})
					return
				}
				if changed {
					scheduleTunnelRestart(cfg)
				}

				zoneID, _, zoneErr := cloudflare.ResolveZoneByHostname(cfg.APIToken, hostname)
				if zoneErr == nil {
					if _, err := cloudflare.DeleteTunnelDNSRecordsByHostname(cfg.APIToken, zoneID, hostname); err != nil {
						log.Printf("[Hostname] Failed to delete DNS for %s: %v", hostname, err)
					}
				}

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

				hostname, err := normalizeHostname(req.Hostname)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}

				cfg, _ := config.GetAppConfig()
				if cfg == nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Not configured"})
					return
				}

				if cfg.SystemHostname != "" {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "System hostname already configured"})
					return
				}

				port := os.Getenv("PORT")
				if port == "" {
					port = "8020"
				}
				service := fmt.Sprintf("http://localhost:%s", port)

				zoneID, _, err := cloudflare.ResolveZoneByHostname(cfg.APIToken, hostname)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}

				if _, err := cloudflare.EnsureTunnelDNSRecord(cfg.APIToken, zoneID, hostname, cfg.TunnelID, "System hostname - Managed by Tunnel Local GUI"); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}

				changed, err := mutateTunnelIngress(cfg, func(ingress []interface{}) ([]interface{}, bool, error) {
					return upsertIngressRule(ingress, hostname, service)
				})
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to update tunnel config: " + err.Error()})
					return
				}

				cfg.SystemHostname = hostname
				if err := config.SaveAppConfig(cfg); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to save system hostname: " + err.Error()})
					return
				}

				if changed {
					scheduleTunnelRestart(cfg)
				}

				c.JSON(http.StatusOK, gin.H{
					"success":  true,
					"hostname": hostname,
					"service":  service,
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
					"success":        true,
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

			// Cloudflared status (for install modal)
			api.GET("/cloudflared-status", func(c *gin.Context) {
				installed := false
				if path, err := exec.LookPath("cloudflared"); err == nil && path != "" {
					installed = true
				}
				// Detect if running in Docker
				inDocker := false
				if _, err := os.Stat("/.dockerenv"); err == nil {
					inDocker = true
				}
				// Detect OS
				osName := "unknown"
				if content, err := os.ReadFile("/etc/os-release"); err == nil {
					for _, line := range strings.Split(string(content), "\n") {
						if strings.HasPrefix(line, "ID=") {
							osName = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
							break
						}
					}
				}
				// Get token if config exists
				tokenHint := ""
				cfg, _ := config.GetAppConfig()
				if cfg != nil && cfg.TunnelToken != "" {
					tokenHint = cfg.TunnelToken
				}
				c.JSON(http.StatusOK, gin.H{
					"success":     true,
					"installed":   installed,
					"in_docker":   inDocker,
					"os":          osName,
					"running":     runner != nil && runner.IsRunning(),
					"token_hint":  tokenHint,
				})
			})

			// Cloudflared install (accepts sudo password for non-root binary mode)
			api.POST("/cloudflared-install", func(c *gin.Context) {
				var req struct {
					SudoPassword string `json:"sudo_password"`
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}

				cfg, _ := config.GetAppConfig()
				if cfg == nil || cfg.TunnelToken == "" {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "FlareGate not configured. Set up tunnel first."})
					return
				}

				// Check if already installed
				if path, err := exec.LookPath("cloudflared"); err == nil && path != "" {
					// Already installed, just start the service
					cmd := exec.Command("sudo", "-S", "systemctl", "restart", "cloudflared")
					cmd.Stdin = strings.NewReader(req.SudoPassword + "\n")
					output, err := cmd.CombinedOutput()
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{
							"success": false,
							"error":   fmt.Sprintf("Failed to restart cloudflared: %s", string(output)),
						})
						return
					}
					c.JSON(http.StatusOK, gin.H{"success": true, "message": "cloudflared service restarted"})
					return
				}

				// Download cloudflared
				archCmd := exec.Command("uname", "-m")
				archOut, _ := archCmd.Output()
				arch := strings.TrimSpace(string(archOut))
				cloudflaredURL := "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
				if arch == "aarch64" {
					cloudflaredURL = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
				}

				// Download cloudflared
				downloadCmd := exec.Command("sudo", "-S", "bash", "-c",
					fmt.Sprintf("curl -L --output /tmp/cloudflared %s && install -m 755 /tmp/cloudflared /usr/local/bin/cloudflared && rm /tmp/cloudflared", cloudflaredURL))
				downloadCmd.Stdin = strings.NewReader(req.SudoPassword + "\n")
				output, err := downloadCmd.CombinedOutput()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{
						"success": false,
						"error":   fmt.Sprintf("Download failed: %s", string(output)),
					})
					return
				}

				// Install as systemd service
				installCmd := exec.Command("sudo", "-S", "cloudflared", "service", "install", cfg.TunnelToken)
				installCmd.Stdin = strings.NewReader(req.SudoPassword + "\n")
				output, err = installCmd.CombinedOutput()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{
						"success": false,
						"error":   fmt.Sprintf("Service install failed: %s", string(output)),
					})
					return
				}

				// Start the service
				startCmd := exec.Command("sudo", "-S", "systemctl", "start", "cloudflared")
				startCmd.Stdin = strings.NewReader(req.SudoPassword + "\n")
				output, err = startCmd.CombinedOutput()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{
						"success": false,
						"error":   fmt.Sprintf("Service start failed: %s", string(output)),
					})
					return
				}

				c.JSON(http.StatusOK, gin.H{"success": true, "message": "cloudflared installed and started as systemd service"})
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

func loadVisibleIngress(cfg *config.Config) ([]interface{}, error) {
	ingress, err := cloudflare.GetTunnelIngress(cfg.AccountID, cfg.TunnelID, cfg.APIToken)
	if err != nil {
		return nil, err
	}
	return cloudflare.VisibleIngressRules(ingress), nil
}

func mutateTunnelIngress(cfg *config.Config, mutator func([]interface{}) ([]interface{}, bool, error)) (bool, error) {
	if cfg == nil {
		return false, fmt.Errorf("nil tunnel config")
	}
	ingress, err := cloudflare.GetTunnelIngress(cfg.AccountID, cfg.TunnelID, cfg.APIToken)
	if err != nil {
		return false, err
	}
	updatedIngress, changed, err := mutator(ingress)
	if err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}
	if err := cloudflare.UpdateTunnelIngress(cfg.AccountID, cfg.TunnelID, cfg.APIToken, updatedIngress); err != nil {
		return false, err
	}
	return true, nil
}

func scheduleTunnelRestart(cfg *config.Config) {
	go func() {
		if err := runner.Restart(cfg); err != nil {
			log.Printf("[Tunnel] Restart failed: %v", err)
		}
	}()
}

func normalizeHostname(hostname string) (string, error) {
	hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if hostname == "" {
		return "", fmt.Errorf("Hostname is required")
	}
	if !strings.Contains(hostname, ".") || strings.ContainsAny(hostname, " /\t\r\n") {
		return "", fmt.Errorf("Hostname must be a valid FQDN")
	}
	return hostname, nil
}

func normalizeService(service string) (string, error) {
	service = strings.TrimSpace(service)
	if service == "" {
		return "", fmt.Errorf("Service is required")
	}
	if strings.Contains(service, "://") {
		return service, nil
	}
	return "http://" + service, nil
}

func buildIngressRule(hostname, service string) map[string]interface{} {
	return map[string]interface{}{
		"hostname": hostname,
		"service":  service,
		"originRequest": map[string]interface{}{
			"noTLSVerify": true,
		},
	}
}

func ingressRuleMatches(rule map[string]interface{}, hostname string) bool {
	existingHostname, _ := rule["hostname"].(string)
	return existingHostname == hostname
}

func ingressRuleEquivalent(rule map[string]interface{}, hostname, service string) bool {
	if !ingressRuleMatches(rule, hostname) {
		return false
	}
	existingService, _ := rule["service"].(string)
	if existingService != service {
		return false
	}
	originRequest, _ := rule["originRequest"].(map[string]interface{})
	noTLSVerify, _ := originRequest["noTLSVerify"].(bool)
	return noTLSVerify
}

func insertIngressRuleBeforeCatchAll(ingress []interface{}, newRule map[string]interface{}) []interface{} {
	newIngress := make([]interface{}, 0, len(ingress)+1)
	inserted := false
	for _, rule := range ingress {
		if !inserted {
			if ruleMap, ok := rule.(map[string]interface{}); ok {
				if _, hasHostname := ruleMap["hostname"]; !hasHostname {
					newIngress = append(newIngress, newRule)
					inserted = true
				}
			}
		}
		newIngress = append(newIngress, rule)
	}
	if !inserted {
		newIngress = append([]interface{}{newRule}, newIngress...)
	}
	return newIngress
}

func upsertIngressRule(ingress []interface{}, hostname, service string) ([]interface{}, bool, error) {
	newRule := buildIngressRule(hostname, service)
	updatedIngress := make([]interface{}, 0, len(ingress))
	found := false
	changed := false

	for _, rule := range ingress {
		ruleMap, ok := rule.(map[string]interface{})
		if ok && ingressRuleMatches(ruleMap, hostname) {
			found = true
			if ingressRuleEquivalent(ruleMap, hostname, service) {
				updatedIngress = append(updatedIngress, rule)
			} else {
				updatedIngress = append(updatedIngress, newRule)
				changed = true
			}
			continue
		}
		updatedIngress = append(updatedIngress, rule)
	}

	if found {
		return updatedIngress, changed, nil
	}

	return insertIngressRuleBeforeCatchAll(ingress, newRule), true, nil
}

func updateExistingIngressRule(ingress []interface{}, hostname, service string) ([]interface{}, bool, bool, error) {
	newRule := buildIngressRule(hostname, service)
	updatedIngress := make([]interface{}, 0, len(ingress))
	found := false
	changed := false

	for _, rule := range ingress {
		ruleMap, ok := rule.(map[string]interface{})
		if ok && ingressRuleMatches(ruleMap, hostname) {
			found = true
			if ingressRuleEquivalent(ruleMap, hostname, service) {
				updatedIngress = append(updatedIngress, rule)
			} else {
				updatedIngress = append(updatedIngress, newRule)
				changed = true
			}
			continue
		}
		updatedIngress = append(updatedIngress, rule)
	}

	return updatedIngress, found, changed, nil
}

func removeIngressRule(ingress []interface{}, hostname string) ([]interface{}, bool, bool, error) {
	updatedIngress := make([]interface{}, 0, len(ingress))
	found := false
	for _, rule := range ingress {
		ruleMap, ok := rule.(map[string]interface{})
		if ok && ingressRuleMatches(ruleMap, hostname) {
			found = true
			continue
		}
		updatedIngress = append(updatedIngress, rule)
	}
	return updatedIngress, found, found, nil
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

func getOrCreateSecretKey() (string, error) {
	// 1. Check Env
	if key := os.Getenv("SECRET_KEY"); key != "" {
		log.Printf("[Init] Using SECRET_KEY from environment")
		return key, nil
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
		if key == "" {
			return "", fmt.Errorf("secret key file %s is empty", keyPath)
		}
		return key, nil
	}

	// 3. Generate
	key, err := generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("generate random key: %w", err)
	}

	// 4. Save
	if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
		return "", fmt.Errorf("save secret key to %s: %w", keyPath, err)
	} else {
		log.Printf("[Init] Generated and saved new SECRET_KEY to %s", keyPath)
	}

	return key, nil
}

func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ── PASETO v4 local (symmetric) helpers ──────────────────────────────

var pasetoKey paseto.V4SymmetricKey

func createPASETOToken(userID uint, username string) (string, error) {
	token := paseto.NewToken()
	token.SetString("user_id", fmt.Sprintf("%d", userID))
	token.SetString("username", username)
	token.SetIssuedAt(time.Now())
	token.SetExpiration(time.Now().Add(7 * 24 * time.Hour))

	return token.V4Encrypt(pasetoKey, nil), nil
}

func validatePASETOToken(encrypted string) (uint, string, error) {
	parser := paseto.NewParser()
	token, err := parser.ParseV4Local(pasetoKey, encrypted, nil)
	if err != nil {
		return 0, "", err
	}

	userIDStr, err := token.GetString("user_id")
	if err != nil {
		return 0, "", err
	}
	username, err := token.GetString("username")
	if err != nil {
		return 0, "", err
	}

	var userID uint
	if _, scanErr := fmt.Sscanf(userIDStr, "%d", &userID); scanErr != nil {
		return 0, "", fmt.Errorf("invalid user_id in token: %w", scanErr)
	}

	return userID, username, nil
}
