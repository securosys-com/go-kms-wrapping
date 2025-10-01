// Copyright (c) 2025 Securosys SA.

package securosyshsm

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"

	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/client"
	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure KeyStore implements KeyStore
var _ kms.KeyStore = (*KeyStore)(nil)

// KeyStore is a KeyStore backed by a Securosys HSM.
// In real life, this would use the Securosys SDK / PKCS#11 library.
var LOGGER = slog.New(slog.NewTextHandler(os.Stdout, nil))

type KeyStore struct {
	provider *kms.CryptoProviderParameters
	client   *client.SecurosysClient
	closed   bool
}

func (s *KeyStore) GenerateRandom(length int) (random []byte, err error) {
	if length < 1 {
		return nil, errors.New("length must be greater than zero")
	}
	generateRandom, _, err := s.client.GenerateRandom(length)
	if err != nil {
		return nil, err
	}
	random, _ = b64.StdEncoding.DecodeString(generateRandom.Random)
	return random, nil

}

func (s *KeyStore) GenerateSecretKey(keyAttributes *kms.KeyAttributes, password ...string) (kms.Key, error) {
	keyType := ""
	switch keyAttributes.KeyType {
	case kms.AESKey:
		keyType = "AES"
		break
	}
	attributes := attributesMapper(keyAttributes)
	keyPassword := ""
	if password != nil && len(password) > 0 {
		keyPassword = password[0]
	}

	key, err := s.client.CreateOrUpdateKey(keyAttributes.Name, keyPassword, attributes, keyType, float64(keyAttributes.BitKeyLen), nil, "", false)
	if err != nil {
		return nil, err
	}

	getKey, err := s.client.GetKey(key, keyPassword)
	if err != nil {
		return nil, err
	}

	return &Key{
		client:   s.client,
		password: keyPassword,
		key:      getKey,
	}, nil
}

func (s *KeyStore) GenerateKeyPair(keyPairAttributes *kms.KeyAttributes, password ...string) (privateKey kms.Key, publicKey kms.Key, err error) {
	keyType := ""
	var curveOid string
	var keySize float64
	switch keyPairAttributes.KeyType {
	case kms.PrivateRSAKey:
		keyType = "RSA"
		curveOid = ""
		keySize = float64(keyPairAttributes.BitKeyLen)
		break
	case kms.PrivateECKey:
		keyType = "EC"
		curveOid = keyPairAttributes.CurveOid
		keySize = 0
		break
	}

	attributes := attributesMapper(keyPairAttributes)
	keyPassword := ""
	if password != nil && len(password) > 0 {
		keyPassword = password[0]
	}

	key, err := s.client.CreateOrUpdateKey(keyPairAttributes.Name, keyPassword, attributes, keyType, keySize, keyPairAttributes.Policy, curveOid, false)
	if err != nil {
		return nil, nil, err
	}

	getKey, err := s.client.GetKey(key, keyPassword)
	if err != nil {
		return nil, nil, err
	}

	return &Key{
			client:   s.client,
			password: keyPassword,
			key:      getKey,
		}, &Key{
			client:   s.client,
			password: keyPassword,
			key:      getKey,
		}, nil
}

func (s *KeyStore) Close() error {
	if s.closed {
		return nil
	}
	// TODO: finalize HSM session
	s.closed = true
	return nil
}

func (s *KeyStore) Login(credentials *kms.Credentials) error {
	s.closed = false
	return nil
}

func (s *KeyStore) ListKeys() ([]kms.Key, error) {
	// TODO: query HSM for key handles
	err := IsConnectionClosed(s.closed)
	if err != nil {
		return nil, err
	}
	keys, err := s.client.GetKeys()
	if err != nil {
		return nil, err
	}
	var mappedKeys []kms.Key
	for _, keyLabel := range keys {
		key, err := s.client.GetKey(keyLabel, "")
		if err == nil {
			//TEMPORARY DISABLE OTHER KEYS
			if key.Algorithm == "RSA" || key.Algorithm == "AES" || key.Algorithm == "EC" {
				mappedKeys = append(mappedKeys, &Key{
					client:   s.client,
					password: "",
					key:      key,
				})

			}
		}

	}
	return mappedKeys, nil
}

func (s *KeyStore) GetKeyById(keyId string, password ...string) (kms.Key, error) {
	keyPassword := ""
	if password != nil && len(password) > 0 {
		keyPassword = password[0]
	}
	key, err := s.client.GetKey(keyId, keyPassword)
	if err != nil {
		return nil, err
	}
	return &Key{
		client:   s.client,
		password: keyPassword,
		key:      key,
	}, nil
}

func (s *KeyStore) GetKeyByName(keyName string, password ...string) (kms.Key, error) {
	keyPassword := ""
	if password != nil && len(password) > 0 {
		keyPassword = password[0]
	}
	key, err := s.client.GetKey(keyName, keyPassword)
	if err != nil {
		return nil, err
	}
	return &Key{
		client:   s.client,
		password: keyPassword,
		key:      key,
	}, nil
}

func (s *KeyStore) RemoveKey(key kms.Key) error {
	err := s.client.RemoveKey(key.GetName())
	if err != nil {
		return err
	}
	return nil
}

// KeyStoreFactory creates KeyStore instances
type KeyStoreFactory struct{}

// Ensure KeyStoreFactory implements KeyStoreFactory
var _ kms.KeyStoreFactory = (*KeyStoreFactory)(nil)

func (f *KeyStoreFactory) NewKeyStore(provider *kms.CryptoProviderParameters) (kms.KeyStore, error) {
	if provider == nil {
		return nil, errors.New("provider parameters required")
	}
	if provider.Params == nil {
		return nil, errors.New("provider.Params parameters required")
	}

	bytes, _ := json.Marshal(provider.Params)
	var config *helpers.SecurosysConfig
	json.Unmarshal(bytes, &config)

	c, err := client.NewClient(config)

	if err != nil {
		return nil, err
	}
	connection, status, err := c.CheckConnection()
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, errors.New(connection)
	}
	//LOGGER.Info(connection)
	return &KeyStore{
		provider: provider,
		client:   c,
		closed:   false,
	}, nil
}

func attributesMapper(keyAttributes *kms.KeyAttributes) map[string]bool {
	var attributes = make(map[string]bool)
	attributes["decrypt"] = keyAttributes.CanDecrypt
	attributes["sign"] = keyAttributes.CanSign
	attributes["unwrap"] = keyAttributes.CanUnwrap
	attributes["verify"] = keyAttributes.CanVerify
	attributes["wrap"] = keyAttributes.CanWrap
	attributes["derive"] = keyAttributes.CanDerive
	attributes["encrypt"] = keyAttributes.CanEncrypt
	attributes["sensitive"] = keyAttributes.IsSensitive
	attributes["extractable"] = keyAttributes.IsExportable
	attributes["destroyable"] = keyAttributes.IsRemovable
	return attributes
}

func IsConnectionClosed(closed bool) error {
	if closed {
		return errors.New("keystore already closed")
	}
	return nil
}
func NewKeyStore(provider *kms.CryptoProviderParameters) (kms.KeyStore, error) {
	factory := &KeyStoreFactory{}
	return factory.NewKeyStore(provider)
}
