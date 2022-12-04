package authutil

import (
	"encoding/json"
	"io"
	"net/http"
)

func GetJwks(url string) (json.RawMessage, error) {
	// TODO: cache jwks

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwksJSON json.RawMessage = b

	return jwksJSON, nil
}
