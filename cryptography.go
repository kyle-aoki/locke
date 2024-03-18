package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"math/big"
)

const pool = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func newEncryptionKey() string {
	length := 32
	var bytes []byte
	for i := 0; i < length; i++ {
		ch := pool[randInt(len(pool))]
		bytes = append(bytes, ch)
	}
	return string(bytes)
}

func randInt(mx int) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(mx)))
	check(err)
	return n.Int64()
}

func encrypt(plaintext []byte, key []byte) []byte {
	if len(key) != 32 {
		panic("invalid aes key size: key must be length of 32")
	}
	block := must(aes.NewCipher(key))
	gcm := must(cipher.NewGCM(block))
	nonce := make([]byte, gcm.NonceSize())
	_ = must(io.ReadFull(rand.Reader, nonce))
	return gcm.Seal(nonce, nonce, plaintext, nil)
}

func decrypt(ciphertext []byte, key []byte) []byte {
	if len(key) != 32 {
		panic("invalid aes key size: key must be length of 32")
	}
	block := must(aes.NewCipher(key))
	gcm := must(cipher.NewGCM(block))
	if len(ciphertext) < gcm.NonceSize() {
		panic("malformed ciphertext")
	}
	return must(gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil))
}
