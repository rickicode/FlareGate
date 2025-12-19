package config

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
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

// User represents a single user account
type User struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Username  string    `gorm:"uniqueIndex;not null" json:"username"`
	Password  string    `gorm:"not null" json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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
	DB.AutoMigrate(&Config{}, &User{})
}

// User-related functions

// CreateUser creates a single user with hashed password
func CreateUser(username, password string) (*User, error) {
	// Check if user already exists
	if HasUsers() {
		return nil, fmt.Errorf("user already exists. Only one user is allowed")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := User{
		Username: username,
		Password: string(hashedPassword),
	}

	result := DB.Create(&user)
	if result.Error != nil {
		return nil, result.Error
	}

	return &user, nil
}

// GetUserByUsername retrieves user by username
func GetUserByUsername(username string) (*User, error) {
	var user User
	result := DB.First(&user, "username = ?", username)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

// ValidateUser validates user credentials
func ValidateUser(username, password string) (*User, error) {
	user, err := GetUserByUsername(username)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, err
	}

	return user, nil
}

// HasUsers checks if any user exists in the database
func HasUsers() bool {
	var count int64
	DB.Model(&User{}).Count(&count)
	return count > 0
}

// GetUser retrieves the single user
func GetUser() (*User, error) {
	var user User
	result := DB.First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

// UpdateUserPassword updates the user's password
func UpdateUserPassword(userID uint, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return DB.Model(&User{}).Where("id = ?", userID).Update("password", string(hashedPassword)).Error
}

// UpdateUserUsername updates the user's username
func UpdateUserUsername(userID uint, newUsername string) error {
	return DB.Model(&User{}).Where("id = ?", userID).Update("username", newUsername).Error
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

func DeleteAppConfig() error {
	return DB.Where("1 = 1").Delete(&Config{}).Error
}
