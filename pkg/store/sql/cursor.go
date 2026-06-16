package sql

import (
	"encoding/base64"
	"encoding/json"

	"github.com/openkcm/krypton/internal/clock"
)

type cursor struct {
	ID        string         `json:"id"`
	CreatedAt clock.UnixNano `json:"created_at"`
}

func NewCursor(id string, createdAt clock.UnixNano) cursor {
	return cursor{
		ID:        id,
		CreatedAt: createdAt,
	}
}

func (c cursor) Encode() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func DecodeCursor(es string) (cursor, error) {
	var c cursor
	b, err := base64.RawURLEncoding.DecodeString(es)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	return c, nil
}
