package entity

import "time"

var (
	NilAuthRequest = AuthRequest{}
)

type AuthRequest struct {
	ID          string     `gorm:"primaryKey;type:string;size:64;comment:id" json:"id"`
	CreatedAt   *time.Time `gorm:"<-:create" json:"created_at,omitempty"`
	UpdatedAt   *time.Time `gorm:"<-" json:"updated_at,omitempty"`
	ResponseUrl string     `gorm:"type:string;size:4096;comment:url to send token data to connected clients;" json:"response_url,omitempty"`
	AuthUrl     string     `gorm:"type:string;size:4096;comment:url to request authorization;" json:"auth_url"`
}
