package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

func parsePublicKey(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to cast parsed key to *rsa.PublicKey")
	}

	return rsaPublicKey, nil
}

func EncryptRSA(text, publicKeyPEM string) (string, error) {
	// 加载公钥
	pubKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return "", err
	}
	if pubKey == nil {
		return "", fmt.Errorf("public key is nil")
	}
	// 加密
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(text))
	if err != nil {
		return "", err
	}
	// base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptRSA(text, privateKeyPEM string) (string, error) {
	// 加载私钥
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block containing the private key")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return "", fmt.Errorf("unsupported key type %q", block.Type)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	// base64
	ciphertext, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}
	// 解密
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
