package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID        uuid.UUID `gorm:"type:uuid;unique;not null"`
	Email         string    `gorm:"type:varchar(255);unique;not null"`
	Password      string    `gorm:"type:text;not null"`
	Role          string    `gorm:"type:varchar(50);not null"`
	IsBlocked     bool      `gorm:"default:false"`
	IsEmailVerified bool      `gorm:"default:false"`
	CreatedAt     time.Time `gorm:"default:now()"`
	UpdatedAt     time.Time `gorm:"default:now()"`
}

type UserDetails struct {
	ID                 uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID             uuid.UUID `gorm:"type:uuid;not null;unique"`
	FirstName          string    `gorm:"type:varchar(255);not null"`
	LastName           string    `gorm:"type:varchar(255);not null"`
	ProfileImage       string    `gorm:"type:varchar(255)"`
	Phone              string    `gorm:"type:varchar(20)"`
	MasterOfCeremonies bool      `gorm:"default:false"`

	User User `gorm:"foreignKey:UserID;references:UserID;constraint:OnDelete:CASCADE"`
}



