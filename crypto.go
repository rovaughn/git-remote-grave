package main

import (
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/nacl/secretbox"
)

var (
	errBoxTooShort = errors.New("payload is too short to decrypt")
	errBoxInvalid  = errors.New("payload failed to decrypt")
)

func decrypt(src []byte, key *[32]byte) ([]byte, error) {
	if len(src) < 24 {
		return nil, errBoxTooShort
	}

	var nonce [24]byte
	copy(nonce[:], src[0:24])

	result, ok := secretbox.Open(nil, src[24:], &nonce, key)
	if !ok {
		return nil, errBoxInvalid
	}

	return result, nil
}

func encrypt(src []byte, key *[32]byte) ([]byte, error) {
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
