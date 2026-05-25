package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
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
	ID             uint   `gorm:"primaryKey" json:"id"`
	AccountID      string `json:"account_id"`
	TunnelID       string `json:"tunnel_id"`
	TunnelName     string `json:"tunnel_name"`
	APIToken       string `json:"-"`
	TunnelToken    string `json:"-"`
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

const encryptedPrefix = "enc:v1:"

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
	apiToken, err := decryptSecretIfNeeded(cfg.APIToken)
	if err != nil {
		return nil, err
	}
	tunnelToken, err := decryptSecretIfNeeded(cfg.TunnelToken)
	if err != nil {
		return nil, err
	}
	cfg.APIToken = apiToken
	cfg.TunnelToken = tunnelToken
	return &cfg, nil
}

func SaveAppConfig(cfg *Config) error {
	apiToken, err := encryptSecretIfNeeded(cfg.APIToken)
	if err != nil {
		return err
	}
	tunnelToken, err := encryptSecretIfNeeded(cfg.TunnelToken)
	if err != nil {
		return err
	}
	copyCfg := *cfg
	copyCfg.APIToken = apiToken
	copyCfg.TunnelToken = tunnelToken

	var existing Config
	if result := DB.First(&existing); result.Error == nil {
		copyCfg.ID = existing.ID
		if copyCfg.AccountID == "" {
			copyCfg.AccountID = existing.AccountID
		}
		if copyCfg.TunnelID == "" {
			copyCfg.TunnelID = existing.TunnelID
		}
		if copyCfg.TunnelName == "" {
			copyCfg.TunnelName = existing.TunnelName
		}
		if copyCfg.SystemHostname == "" {
			copyCfg.SystemHostname = existing.SystemHostname
		}
		// Preserve encrypted secrets if empty in update.
		if copyCfg.TunnelToken == "" {
			copyCfg.TunnelToken = existing.TunnelToken
		}
		if copyCfg.APIToken == "" {
			copyCfg.APIToken = existing.APIToken
		}
		return DB.Save(&copyCfg).Error
	}
	return DB.Create(&copyCfg).Error
}

func DeleteAppConfig() error {
	return DB.Where("1 = 1").Delete(&Config{}).Error
}

func encryptSecretIfNeeded(value string) (string, error) {
	if value == "" || isEncryptedValue(value) {
		return value, nil
	}
	key, err := getEncryptionKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)
	return encryptedPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptSecretIfNeeded(value string) (string, error) {
	if value == "" || !isEncryptedValue(value) {
		return value, nil
	}
	key, err := getEncryptionKey()
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(value[len(encryptedPrefix):])
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("encrypted secret too short")
	}
	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func isEncryptedValue(value string) bool {
	return len(value) > len(encryptedPrefix) && value[:len(encryptedPrefix)] == encryptedPrefix
}

func getEncryptionKey() ([]byte, error) {
	secret := os.Getenv("SECRET_KEY")
	if secret == "" {
		content, err := os.ReadFile("data/secret.key")
		if err != nil {
			return nil, fmt.Errorf("read secret key for config encryption: %w", err)
		}
		secret = string(content)
	}
	secret = fmt.Sprintf("%s", secret)
	if secret == "" {
		return nil, fmt.Errorf("secret key is empty")
	}
	sum := sha256.Sum256([]byte(secret))
	return sum[:], nil
}
