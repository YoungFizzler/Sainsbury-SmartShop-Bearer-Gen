package sainsencrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
)

type C4506b struct {
	PublicKey          *rsa.PublicKey
	KeyGenerator       func() ([]byte, error)
	ErrorLoggerService *ErrorLoggerService
	aesCipher          cipher.Block
}

type ErrorLoggerService struct{}

func (e *ErrorLoggerService) Error(name string, err error) {
	log.Printf("Error in %s: %v", name, err)
}

func NewC4506b(publicKeyStr string, keyGenerator func() ([]byte, error), errorLoggerService *ErrorLoggerService) (*C4506b, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil {
		return nil, err
	}

	pubKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	key, err := keyGenerator()
	if err != nil {
		return nil, err
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &C4506b{
		PublicKey:          rsaPubKey,
		KeyGenerator:       keyGenerator,
		ErrorLoggerService: errorLoggerService,
		aesCipher:          aesCipher,
	}, nil
}

func (c *C4506b) m19284a(bytesData []byte) (string, error) {
	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, c.PublicKey, bytesData)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

func (c *C4506b) m19285b(str string) (string, error) {
	bytesData := []byte(str)
	encryptedStr, err := c.m19284a(bytesData)
	if err != nil {
		c.ErrorLoggerService.Error("C4506b", err)
		return "", err
	}
	return encryptedStr, nil
}

func m19898b(c *C4506b) (string, error) {
	authTokenBuilder := fmt.Sprintf("ss_android_mobile_1k#%s#%s", time.Now().Format("2006-01-02 15:04:05"), uuid.New().String())
	encryptedAuthToken, err := c.m19285b(authTokenBuilder)
	if err != nil {
		return "", err
	}

	str2 := fmt.Sprintf("ss_android_mobile_1k:%s", encryptedAuthToken)
	encodedData := base64.StdEncoding.EncodeToString([]byte(str2))
	return fmt.Sprintf("Basic %s", encodedData), nil
}

func Initialise() *C4506b {
	publicKeyStr := "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRn+iPY/ENsTQpLsyIDPK/HRzvirt81Wc8Nl9Iv/Vt10hSsefW98j1vo0RaBOYUYpVeSaM13C/r0LqSFkF/gC6t5vrU3bJ6vLfLg9IDx33h+G5aT78ZHyVdj1VBiJBIQxmd9tV+xphm1dQsptZEzJ2t/0Y7U7BSRu35ERVxi+HzwIDAQAB"
	keyGenerator := func() ([]byte, error) {
		key := make([]byte, 16)
		_, err := rand.Read(key)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	errorLoggerService := &ErrorLoggerService{}

	c4506bInstance, err := NewC4506b(publicKeyStr, keyGenerator, errorLoggerService)
	if err != nil {
		log.Fatalf("Failed to create C4506b instance: %v", err)
	}
	return c4506bInstance
}

func (c *C4506b) Encrypt() string {
	result, err := m19898b(c)
	if err != nil {
		log.Fatalf("Failed to generate auth token: %v", err)
	}
	fmt.Println("[SAINSBURYS-TOKEN] Generated auth token:", result)
	return result
}
