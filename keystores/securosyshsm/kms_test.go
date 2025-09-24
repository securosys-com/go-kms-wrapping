package securosyshsm

import (
	"errors"
	"fmt"
	"testing"

	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/assert"
)

var provider = &kms.CryptoProviderParameters{
	KeystoreProvider: "securosys-hsm",
	Params: map[string]interface{}{
		"restapi": "TSB_URL",
		"auth":    "NONE",
	},
}
var AES_KEY_NAME = "KEY1"
var RSA_KEY_NAME = "KEY2"

func TestKMS(t *testing.T) {
	t.Run("Keystore: Init", func(t *testing.T) {
		_, err := NewKeyStore(provider)
		assert.NoError(t, err)

	})
	t.Run("Keystore: GenerateSecretKey", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		key, err := keystore.GenerateSecretKey(&kms.KeyAttributes{
			KeyType:     kms.AESKey,
			Name:        "AES_KEY_OPENBAO_TEST",
			BitKeyLen:   256,
			IsRemovable: true,
		}, "")
		assert.NoError(t, err)

		if key.GetName() != "AES_KEY_OPENBAO_TEST" {
			assert.NoError(t, errors.New(fmt.Sprintf("Key label is not correct. Want %s got %s", "AES_KEY_OPENBAO_TEST", key.GetName())))
		}

	})
	t.Run("Keystore: RemoveKey", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		key, err := keystore.GetKeyByName("AES_KEY_OPENBAO_TEST")
		assert.NoError(t, err)
		err = keystore.RemoveKey(key)
		assert.NoError(t, err)

	})
	t.Run("Keystore: ListKeys", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		keys, err := keystore.ListKeys()
		if err != nil {
			assert.NoError(t, err)
		}
		if len(keys) == 0 {
			assert.NoError(t, errors.New("no keys found"))
		}
	})
	t.Run("Keystore: GetKeyByName", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		key, err := keystore.GetKeyByName(AES_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key.GetName() != AES_KEY_NAME {
			assert.NoError(t, errors.New(fmt.Sprintf("Key label is not correct. Want %s got %s", AES_KEY_NAME, key.GetName())))
		}
		if key.GetType() != kms.AESKey {
			assert.NoError(t, errors.New(fmt.Sprintf("Key type is not correct. Want %d got %d", kms.AESKey, key.GetType())))
		}
		if key.GetLength() != 256 {
			assert.NoError(t, errors.New(fmt.Sprintf("Key size is not correct. Want %d got %d", 256, key.GetLength())))
		}
	})
	t.Run("Keystore: GetKeyById", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		key, err := keystore.GetKeyById(RSA_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key.GetName() != RSA_KEY_NAME {
			assert.NoError(t, errors.New(fmt.Sprintf("Key label is not correct. Want %s got %s", RSA_KEY_NAME, key.GetName())))
		}
		if key.GetType() != kms.PrivateRSAKey {
			assert.NoError(t, errors.New(fmt.Sprintf("Key type is not correct. Want %d got %d", kms.PrivateRSAKey, key.GetType())))
		}
		if key.GetLength() != 2048 {
			assert.NoError(t, errors.New(fmt.Sprintf("Key size is not correct. Want %d got %d", 2048, key.GetLength())))
		}
	})
	t.Run("Keystore: DeleteKey", func(t *testing.T) {
		//TODO: After create keu is ready
	})
	t.Run("Key: GetName", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		key1, err := keystore.GetKeyByName(AES_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key1.GetName() != AES_KEY_NAME {
			assert.NoError(t, errors.New(fmt.Sprintf("Key label is not correct. Want %s got %s", AES_KEY_NAME, key1.GetName())))
		}
		key2, err := keystore.GetKeyByName(RSA_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key1.GetName() != AES_KEY_NAME {
			assert.NoError(t, errors.New(fmt.Sprintf("Key label is not correct. Want %s got %s", RSA_KEY_NAME, key2.GetName())))
		}
	})
	t.Run("Key: GetType", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		key1, err := keystore.GetKeyByName(AES_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key1.GetType() != kms.AESKey {
			assert.NoError(t, errors.New(fmt.Sprintf("Key type is not correct. Want %d got %d", kms.AESKey, key1.GetType())))
		}
		key2, err := keystore.GetKeyByName(RSA_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key2.GetType() != kms.PrivateRSAKey {
			assert.NoError(t, errors.New(fmt.Sprintf("Key type is not correct. Want %d got %d", kms.PrivateRSAKey, key2.GetType())))
		}
	})
	t.Run("Key: GetLength", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		key1, err := keystore.GetKeyByName(AES_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key1.GetLength() != 256 {
			assert.NoError(t, errors.New(fmt.Sprintf("Key size is not correct. Want %d got %d", 256, key1.GetLength())))
		}
		key2, err := keystore.GetKeyByName(RSA_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key2.GetLength() != 2048 {
			assert.NoError(t, errors.New(fmt.Sprintf("Key size is not correct. Want %d got %d", 2048, key2.GetLength())))
		}
	})

}
