package main

import (
	"embed"
	"encoding/gob"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"flaregate/internal/config"
	"flaregate/internal/cloudflare"
	"flaregate/internal/tunnel"
)

//go:embed templates/* static/*
var f embed.FS

var LogFile = "data/cloudflared.log"
var runner *tunnel.Runner

func main() {
	if err := godotenv.Load(); err != nil {
		// log.Println("No .env found")
	}

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
	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		secretKey = "secret"
	}
	adminUser := os.Getenv("ADMIN_USERNAME")
	adminPass := os.Getenv("ADMIN_PASSWORD")

	// Session Middleware
	gob.Register(map[string]interface{}{})
	store := cookie.NewStore([]byte(secretKey))
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
		user := session.Get("user")
		if user == nil {
			if c.Request.Header.Get("X-Requested-With") == "XMLHttpRequest" || strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			} else {
				c.Redirect(http.StatusFound, "/login")
			}
			c.Abort()
			return
		}
		c.Next()
	}

	// Login Routes
	r.GET("/login", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("user") != nil {
			c.Redirect(http.StatusFound, "/")
			return
		}
		c.HTML(http.StatusOK, "login.html", gin.H{})
	})

	r.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		if username == adminUser && password == adminPass {
			session := sessions.Default(c)
			session.Set("user", username)
			session.Save()
			c.Redirect(http.StatusFound, "/")
		} else {
			c.HTML(http.StatusOK, "login.html", gin.H{"error": "Invalid credentials"})
		}
	})

	r.GET("/logout", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Delete("user")
		session.Save()
		c.Redirect(http.StatusFound, "/login")
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

					// Parse service URL
					serviceURL := service
					if !strings.HasPrefix(serviceURL, "http://") && !strings.HasPrefix(serviceURL, "https://") {
						serviceURL = "http://" + serviceURL
					}

					// Try to connect to the origin service
					start := time.Now()
					conn, err := net.DialTimeout("tcp", extractHostPort(serviceURL), 3*time.Second)
					if err == nil {
						conn.Close()
						originStatus = "online"
						originResponseTime = int(time.Since(start).Milliseconds())
					}

					// Check tunnel health (if tunnel is running and service is accessible)
					tunnelStatus := "offline"
					if tunnelRunning && originStatus == "online" {
						// Try to check if the service is accessible through the tunnel
						start = time.Now()
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
				_, status, err := cloudflare.Request("GET", "/user/tokens/verify", req.Token, nil)
				if err != nil || status != 200 {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid token"})
					return
				}
				accsRes, _, err := cloudflare.Request("GET", "/accounts", req.Token, nil)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}
				resultList, ok := accsRes["result"].([]interface{})
				if !ok || len(resultList) == 0 {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "No accounts found"})
					return
				}
				firstAcc := resultList[0].(map[string]interface{})
				accountID := firstAcc["id"].(string)

				tunnelsRes, _, err := cloudflare.Request("GET", fmt.Sprintf("/accounts/%s/tunnels?is_deleted=false", accountID), req.Token, nil)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
					return
				}

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
					"comment": "Managed by Tunnel Local GUI",
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
				
				// Insert at beginning, but before catch-all
				newIngress := append([]interface{}{newRule}, ingress...)

				// Save Config
				updateBody := map[string]interface{}{
					"config": map[string]interface{}{
						"ingress": newIngress,
					},
				}
				
				saveRes, code, err := cloudflare.Request("PUT", confUrl, cfg.APIToken, updateBody)
				if err != nil || code != 200 {
					c.JSON(code, gin.H{"success": false, "error": "Failed to update tunnel config"})
					return
				}
				if s, ok := saveRes["success"].(bool); !ok || !s {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Cloudflare rejected config update"})
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

				// Insert at beginning of ingress rules
				newIngress := make([]interface{}, 0, len(ingress)+1)
				newIngress = append(newIngress, newRule)
				newIngress = append(newIngress, ingress...)

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
	// Default to port 80 if not specified
	if !strings.Contains(serviceURL, ":") {
		return serviceURL + ":80"
	}

	// Extract host:port part
	parts := strings.Split(serviceURL, "/")
	if len(parts) >= 3 && parts[0] != "" {
		// URL format: http://host:port/path
		return parts[2]
	}

	// Already in host:port format
	return serviceURL
}

// Helper function to get keys from a map for debugging
func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

