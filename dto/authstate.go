package dto

import "time"

var (
	NilAuthState = AuthState{}
)

type AuthState struct {
	State     string     `json:"state,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`

	CodeVerifier  string `json:"code_verifier,omitempty"`
	AuthRequestID string `json:"auth_request_id,omitempty"`
}
