package model

import (
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Client struct {
	ID           string `gorm:"primaryKey" json:"id"`
	Name         string `gorm:"not null" json:"name"`
	Username     string `gorm:"uniqueIndex" json:"username"`
	WGPublicKey  string `gorm:"column:wg_public_key;uniqueIndex" json:"wg_public_key"`
	Password     string `gorm:"-" json:"password,omitempty"`
	PasswordHash string `gorm:"column:password_hash" json:"-"`
}

func NewClient(name, username, password, wgPublicKey string) (Client, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return Client{}, err
	}
	return Client{
		ID:           uuid.NewString(),
		Name:         name,
		Username:     username,
		PasswordHash: string(hash),
		WGPublicKey:  wgPublicKey,
	}, nil
}
