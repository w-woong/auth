package dto

import "time"

var (
	NilAuthRequest = AuthRequest{}
)

type AuthRequest struct {
	ID          string     `json:"id"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
	ResponseUrl string     `json:"response_url,omitempty"`
	AuthUrl     string     `json:"auth_url"`
}
