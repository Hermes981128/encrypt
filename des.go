package main

import (
	"bytes"
	"crypto/des"
	"encoding/base64"
)

func pkcs7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}
func EncryptDES_ECB(key, plaintext string) (string, error) {
	block, err := des.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	paddedPlaintext := pkcs7Padding([]byte(plaintext), block.BlockSize())
	ciphertext := make([]byte, len(paddedPlaintext))
	dst := ciphertext
	for len(paddedPlaintext) > 0 {
		block.Encrypt(dst, paddedPlaintext)
		paddedPlaintext = paddedPlaintext[block.BlockSize():]
		dst = dst[block.BlockSize():]
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptDES(key, ciphertext string) (string, error) {
	block, err := des.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	decodedCiphertext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	plaintext := make([]byte, len(decodedCiphertext))
	dst := plaintext
	for len(decodedCiphertext) > 0 {
		block.Decrypt(dst, decodedCiphertext)
		decodedCiphertext = decodedCiphertext[block.BlockSize():]
		dst = dst[block.BlockSize():]
	}
	return string(plaintext), nil
}
