package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Config represents the application configuration
type Config struct {
	ID            uint   `gorm:"primaryKey" json:"id"`
	AccountID     string `json:"account_id"`
	TunnelID      string `json:"tunnel_id"`
	TunnelName    string `json:"tunnel_name"`
	APIToken      string `json:"api_token"`
	TunnelToken   string `json:"tunnel_token"`
	SystemHostname string `json:"system_hostname"`
}

var DB *gorm.DB

func InitDB() {
	// Ensure data dir
	if err := os.MkdirAll("data", 0755); err != nil {
		log.Fatal("Failed to create data directory:", err)
	}

	var err error
	DB, err = gorm.Open(sqlite.Open("data/tunnel.db"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatal("failed to connect database")
	}

	// Migrate
	DB.AutoMigrate(&Config{})

	// Load Env
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}
}

func GetAppConfig() (*Config, error) {
	var cfg Config
	result := DB.First(&cfg)
	if result.Error != nil {
		return nil, result.Error
	}
	return &cfg, nil
}

func SaveAppConfig(cfg *Config) error {
	var existing Config
	if result := DB.First(&existing); result.Error == nil {
		cfg.ID = existing.ID
		// Preserve Token if empty in update (though usually we pass full object)
		if cfg.TunnelToken == "" {
			cfg.TunnelToken = existing.TunnelToken
		}
		return DB.Save(cfg).Error
	}
	return DB.Create(cfg).Error
}
