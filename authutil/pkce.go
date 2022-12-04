package authutil

import (
	"crypto/sha256"
	"encoding/base64"
	"math/rand"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

// The following sets up the requirements for generating a standards compliant PKCE code verifier.
const codeVerifierLenMin = 43
const codeVerifierLenMax = 128
const codeVerifierAllowedLetters = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ._~"

// generateCodeVerifier provides an easy way to generate an n-length randomised
// code verifier.
func GenerateCodeVerifier(n int) string {
	// Enforce standards compliance...
	if n < codeVerifierLenMin {
		n = codeVerifierLenMin
	}
	if n > codeVerifierLenMax {
		n = codeVerifierLenMax
	}

	// Randomly choose some allowed characters...
	b := make([]byte, n)
	for i := range b {
		j := rand.Intn(len(codeVerifierAllowedLetters))
		// ensure we use non-deterministic random ints.
		// j, _ := rand.Int(rand.Reader, big.NewInt(int64(len(codeVerifierAllowedLetters))))
		b[i] = codeVerifierAllowedLetters[j]
	}

	return string(b)
}

// generateCodeChallenge returns a standards compliant PKCE S(HA)256 code
// challenge.
func GenerateCodeChallenge(codeVerifier string) string {
	// Create a sha-265 hash from the code verifier...
	s256 := sha256.New()
	s256.Write([]byte(codeVerifier))

	// Then base64 encode the hash sum to create a code challenge...
	return base64.RawURLEncoding.EncodeToString(s256.Sum(nil))
}
