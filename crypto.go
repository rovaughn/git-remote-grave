package main

import (
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/nacl/secretbox"
)

var (
	ErrBoxTooShort = errors.New("Payload is too short to decrypt.")
	ErrBoxInvalid  = errors.New("Payload failed to decrypt.")
)

func Decrypt(src []byte, key *[32]byte) ([]byte, error) {
	if len(src) < 24 {
		return nil, ErrBoxTooShort
	}

	var nonce [24]byte
	copy(nonce[:], src[0:24])

	if result, ok := secretbox.Open(nil, src[24:], &nonce, key); !ok {
		return nil, ErrBoxInvalid
	} else {
		return result, nil
	}
}

func Encrypt(src []byte, key *[32]byte) ([]byte, error) {
	var nonce [24]byte

	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	result := make([]byte, 24+secretbox.Overhead+len(src))
	sealed := secretbox.Seal(nil, src, &nonce, key)

	copy(result[0:24], nonce[:])
	copy(result[24:], sealed)

	return result, nil
}
