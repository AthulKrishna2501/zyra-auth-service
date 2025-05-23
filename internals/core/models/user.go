package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID              uuid.UUID `gorm:"type:uuid;default:gen_random_uuid()"`
	UserID          uuid.UUID `gorm:"type:uuid;primaryKey;not null;uniqueIndex"`
	Email           string    `gorm:"type:varchar(255);unique;not null"`
	Password        string    `gorm:"type:text;not null"`
	Role            string    `gorm:"type:varchar(50);not null;check:role IN ('vendor', 'client', 'admin')"`
	IsBlocked       bool      `gorm:"default:false"`
	IsEmailVerified bool      `gorm:"default:false"`
	SSOProvider     string    `gorm:"type:varchar(255)"`
	SSOUserID       string    `gorm:"type:varchar(255)"`
	Status          string    `gorm:"type:varchar(255);default:'pending'"`
	CreatedAt       time.Time `gorm:"default:now()"`
	UpdatedAt       time.Time `gorm:"default:now()"`
}

type UserDetails struct {
	ID                 uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID             uuid.UUID `gorm:"type:uuid;not null;unique"`
	FirstName          string    `gorm:"type:varchar(255);not null"`
	LastName           string    `gorm:"type:varchar(255);not null"`
	ProfileImage       string    `gorm:"type:varchar(255)"`
	Phone              string    `gorm:"type:varchar(20)"`
	MasterOfCeremonies bool      `gorm:"default:false"`

	User *User `gorm:"foreignKey:UserID;references:UserID;constraint:OnDelete:CASCADE"`
}
