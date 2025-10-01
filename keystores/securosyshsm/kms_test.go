// Copyright (c) 2025 Securosys SA.

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
		"restapi": "https://engineering.securosys.com/tsb-demo",
		"auth":    "NONE",
		//"bearertoken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJzYngtcmVzdC1hcGkiLCJ2ZXIiOjEsIm5iZiI6MTc1Mzg4NTQyNSwib25ib2FyZFBhcnRpdGlvbiI6InRydWUiLCJpc3MiOiJTZWN1cm9zeXMgQ2xvdWQgQXV0aG9yaXphdGlvbiBTZXJ2aWNlIiwicGF0VFNCIjoibUpZcGV4YWxXYXFXRlFOcGhVWjRtQ3c5TmRJYjFCXC8rZzJPVXVMaXVYZkh3S25aVG01Q3JRWHFUczNxNnM2ZHltUjhFZWFDY2xHcnBOMlNjaWJxRUptNWVDTEM4S3ZWTGdyQlRneTBGWGM4aVRjT3Bzb2NXRmJDTUFaVEQ0NHpEUisyK0NFSEI4YmhFQWRjZWYzMmZSSDIySTVKbmdyQXhUU0paYlJGWHA0bkQrTk5VMmxUUUVMT21aYjBBQjJLXC9uWUVZR1V3NmtwdTQ3dFwvcXh1YnplSFN2R2RQZmRLMmZCNk12RGl3UDVJb1h0enhLOHZqYlVoZUthKzdTbWVBNjJZWENBbENSNWRNN25ZTEdWckltVVpJUFFXV2hLV2hkSVV0RkZuWTBncnV1SEVjWUJ2MHV1VWFnaTN2aUNkNElxTE4wWWJhVkZFdFJRTFNSZFZRWHBrZmJyUT09IiwiZXhwIjozMzMxMDgzNzQyNSwiaWF0IjoxNzUzODg1NDI1LCJub25jZSI6eyJzYWx0Ijoib1dRZTRFaStwcUJkR2ZZbmk4Y08xdz09IiwiaXYiOiIwMlFScUxPYjhkNGFwZDk4In19.yf944qt_oGwkI2ORZP2Ts7xeky6AsmmpUX53FMncE9KEhnt9skVCjVwTPQvV7Xt0Le6nLF9NvluL3aydrWDhZ76waFIkmQRRth-gWBgTzwxFGUFAWSPQWSXMXJqLWnYylNutWTy4IXCzJy0SS3nmtakAE46YMjR_4WE-wI1Y5dFwHaChSkqE72-uNxqJutNy8zh5AarTIa3LiF1iGHmFbK12Cjg8_pPJaSy67CNoBUOBxpoeoyL_thAC0hsnWOnwCZS_SsbqQglifbVEf9ke_PrShTQwCHCCIbbGSCGgtmnhifu1wU-aO-kFrBksqRi84b0LcDOb3-cpyaE70_yuUA",
	},
}
var AES_KEY_NAME = "aes_tee_key"
var RSA_KEY_NAME = "output_key_tee"

func GenerateTestKeyAES(keystore kms.KeyStore) (kms.Key, error) {
	key, err := keystore.GetKeyByName("OPENBAO_AES_TEST_KEY")
	if key != nil {
		return key, nil
	}
	key, err = keystore.GenerateSecretKey(&kms.KeyAttributes{
		KeyType:     kms.AESKey,
		Name:        "OPENBAO_AES_TEST_KEY",
		BitKeyLen:   256,
		IsRemovable: true,
		CanDecrypt:  true,
		CanEncrypt:  true,
	}, "")
	return key, err
}
func GenerateTestKeyRSA(keystore kms.KeyStore) (kms.Key, error) {
	key, err := keystore.GetKeyByName("OPENBAO_RSA_TEST_KEY")
	if key != nil {
		return key, nil
	}
	privateKey, _, err := keystore.GenerateKeyPair(&kms.KeyAttributes{
		KeyType:     kms.PrivateRSAKey,
		Name:        "OPENBAO_RSA_TEST_KEY",
		BitKeyLen:   2048,
		IsRemovable: true,
		CanDecrypt:  true,
		CanEncrypt:  true,
		CanSign:     true,
		CanVerify:   true,
	}, "")
	return privateKey, err
}
func GenerateTestKeyEC(keystore kms.KeyStore) (kms.Key, error) {
	key, err := keystore.GetKeyByName("OPENBAO_EC_TEST_KEY")
	if key != nil {
		return key, nil
	}
	privateKey, _, err := keystore.GenerateKeyPair(&kms.KeyAttributes{
		KeyType:     kms.PrivateECKey,
		Name:        "OPENBAO_EC_TEST_KEY",
		CurveOid:    "1.3.132.0.34",
		IsRemovable: true,
		CanDecrypt:  true,
		CanEncrypt:  true,
		CanSign:     true,
		CanVerify:   true,
	}, "")
	return privateKey, err
}
func RemoveKey(key kms.Key, keystore kms.KeyStore) error {
	err := keystore.RemoveKey(key)
	return err
}

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
			Name:        "AES_KEY_OPENBAO_TEST_CREATE_KEY",
			BitKeyLen:   256,
			IsRemovable: true,
		}, "")
		assert.NoError(t, err)

		if key.GetName() != "AES_KEY_OPENBAO_TEST_CREATE_KEY" {
			assert.NoError(t, errors.New(fmt.Sprintf("Key label is not correct. Want %s got %s", "AES_KEY_OPENBAO_TEST", key.GetName())))
		}

	})
	t.Run("Keystore: RemoveKey", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		key, err := keystore.GetKeyByName("AES_KEY_OPENBAO_TEST_CREATE_KEY", "")
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
		key, err := keystore.GetKeyByName(AES_KEY_NAME, "")
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
		key, err := keystore.GetKeyById(RSA_KEY_NAME, "")
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
		key1, err := keystore.GetKeyByName(AES_KEY_NAME, "")
		if err != nil {
			assert.NoError(t, err)
		}
		if key1.GetName() != AES_KEY_NAME {
			assert.NoError(t, errors.New(fmt.Sprintf("Key label is not correct. Want %s got %s", AES_KEY_NAME, key1.GetName())))
		}
		key2, err := keystore.GetKeyByName(RSA_KEY_NAME, "")
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
		key1, err := keystore.GetKeyByName(AES_KEY_NAME, "")
		if err != nil {
			assert.NoError(t, err)
		}
		if key1.GetType() != kms.AESKey {
			assert.NoError(t, errors.New(fmt.Sprintf("Key type is not correct. Want %d got %d", kms.AESKey, key1.GetType())))
		}
		key2, err := keystore.GetKeyByName(RSA_KEY_NAME, "")
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
		key1, err := keystore.GetKeyByName(AES_KEY_NAME, "")
		if err != nil {
			assert.NoError(t, err)
		}
		if key1.GetLength() != 256 {
			assert.NoError(t, errors.New(fmt.Sprintf("Key size is not correct. Want %d got %d", 256, key1.GetLength())))
		}
		key2, err := keystore.GetKeyByName(RSA_KEY_NAME, "")
		if err != nil {
			assert.NoError(t, err)
		}
		if key2.GetLength() != 2048 {
			assert.NoError(t, errors.New(fmt.Sprintf("Key size is not correct. Want %d got %d", 2048, key2.GetLength())))
		}
	})
	t.Run("Encrypt/Decrypt: Cipher_AES_GCM", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		aesKey, err := GenerateTestKeyAES(keystore)
		assert.NoError(t, err)
		cipherEncrypt, err := NewCipher(kms.Encrypt, aesKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_AES_GCM,
		})
		assert.NoError(t, err)
		update, err := cipherEncrypt.Update([]byte("te"))
		if update == nil {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
		}
		if string(update) != "te" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
		}
		assert.NoError(t, err)
		encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
		assert.NoError(t, err)

		decryptCipher, err := NewCipher(kms.Decrypt, aesKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_AES_GCM,
			IV:        iv,
			MAC:       mac,
		})
		payload, _, _, err := decryptCipher.Close(encryptedPayload)
		assert.NoError(t, err)
		if string(payload) != "test" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
		}
		err = RemoveKey(aesKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Encrypt/Decrypt: Cipher_AES_ECB", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		aesKey, err := GenerateTestKeyAES(keystore)
		assert.NoError(t, err)
		cipherEncrypt, err := NewCipher(kms.Encrypt, aesKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_AES_ECB,
		})
		assert.NoError(t, err)
		update, err := cipherEncrypt.Update([]byte("te"))
		if update == nil {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
		}
		if string(update) != "te" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
		}
		assert.NoError(t, err)
		encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
		assert.NoError(t, err)

		decryptCipher, err := NewCipher(kms.Decrypt, aesKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_AES_ECB,
			IV:        iv,
			MAC:       mac,
		})
		payload, _, _, err := decryptCipher.Close(encryptedPayload)
		assert.NoError(t, err)
		if string(payload) != "test" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
		}
		err = RemoveKey(aesKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Encrypt/Decrypt: Cipher_AES_CTR", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		aesKey, err := GenerateTestKeyAES(keystore)
		assert.NoError(t, err)
		cipherEncrypt, err := NewCipher(kms.Encrypt, aesKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_AES_CTR,
		})
		assert.NoError(t, err)
		update, err := cipherEncrypt.Update([]byte("te"))
		if update == nil {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
		}
		if string(update) != "te" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
		}
		assert.NoError(t, err)
		encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
		assert.NoError(t, err)

		decryptCipher, err := NewCipher(kms.Decrypt, aesKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_AES_CTR,
			IV:        iv,
			MAC:       mac,
		})
		payload, _, _, err := decryptCipher.Close(encryptedPayload)
		assert.NoError(t, err)
		if string(payload) != "test" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
		}
		err = RemoveKey(aesKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Encrypt/Decrypt: Cipher_AES_CBC", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		aesKey, err := GenerateTestKeyAES(keystore)
		assert.NoError(t, err)
		cipherEncrypt, err := NewCipher(kms.Encrypt, aesKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_AES_CBC,
		})
		assert.NoError(t, err)
		update, err := cipherEncrypt.Update([]byte("te"))
		if update == nil {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
		}
		if string(update) != "te" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
		}
		assert.NoError(t, err)
		encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
		assert.NoError(t, err)

		decryptCipher, err := NewCipher(kms.Decrypt, aesKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_AES_CBC,
			IV:        iv,
			MAC:       mac,
		})
		payload, _, _, err := decryptCipher.Close(encryptedPayload)
		assert.NoError(t, err)
		if string(payload) != "test" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
		}
		err = RemoveKey(aesKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Encrypt/Decrypt: Cipher_RSA_MODE", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(keystore)
		assert.NoError(t, err)
		cipherEncrypt, err := NewCipher(kms.Encrypt, rsaKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_RSA_MODE,
		})
		assert.NoError(t, err)
		update, err := cipherEncrypt.Update([]byte("te"))
		if update == nil {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
		}
		if string(update) != "te" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
		}
		assert.NoError(t, err)
		encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
		assert.NoError(t, err)

		decryptCipher, err := NewCipher(kms.Decrypt, rsaKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_RSA_MODE,
			IV:        iv,
			MAC:       mac,
		})
		payload, _, _, err := decryptCipher.Close(encryptedPayload)
		assert.NoError(t, err)
		if string(payload) != "test" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
		}
		err = RemoveKey(rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Encrypt/Decrypt: Cipher_RSA_PADDING_OAEP", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(keystore)
		assert.NoError(t, err)
		cipherEncrypt, err := NewCipher(kms.Encrypt, rsaKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_RSA_PADDING_OAEP,
		})
		assert.NoError(t, err)
		update, err := cipherEncrypt.Update([]byte("te"))
		if update == nil {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
		}
		if string(update) != "te" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
		}
		assert.NoError(t, err)
		encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
		assert.NoError(t, err)

		decryptCipher, err := NewCipher(kms.Decrypt, rsaKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_RSA_PADDING_OAEP,
			IV:        iv,
			MAC:       mac,
		})
		payload, _, _, err := decryptCipher.Close(encryptedPayload)
		assert.NoError(t, err)
		if string(payload) != "test" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
		}
		err = RemoveKey(rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Encrypt/Decrypt: Cipher_RSA_PADDING_OAEP_SHA1", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(keystore)
		assert.NoError(t, err)
		cipherEncrypt, err := NewCipher(kms.Encrypt, rsaKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_RSA_PADDING_OAEP_SHA1,
		})
		assert.NoError(t, err)
		update, err := cipherEncrypt.Update([]byte("te"))
		if update == nil {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
		}
		if string(update) != "te" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
		}
		assert.NoError(t, err)
		encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
		assert.NoError(t, err)

		decryptCipher, err := NewCipher(kms.Decrypt, rsaKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_RSA_PADDING_OAEP_SHA1,
			IV:        iv,
			MAC:       mac,
		})
		payload, _, _, err := decryptCipher.Close(encryptedPayload)
		assert.NoError(t, err)
		if string(payload) != "test" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
		}
		err = RemoveKey(rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Encrypt/Decrypt: Cipher_RSA_PADDING_OAEP_SHA224", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(keystore)
		assert.NoError(t, err)
		cipherEncrypt, err := NewCipher(kms.Encrypt, rsaKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_RSA_PADDING_OAEP_SHA224,
		})
		assert.NoError(t, err)
		update, err := cipherEncrypt.Update([]byte("te"))
		if update == nil {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
		}
		if string(update) != "te" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
		}
		assert.NoError(t, err)
		encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
		assert.NoError(t, err)

		decryptCipher, err := NewCipher(kms.Decrypt, rsaKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_RSA_PADDING_OAEP_SHA224,
			IV:        iv,
			MAC:       mac,
		})
		payload, _, _, err := decryptCipher.Close(encryptedPayload)
		assert.NoError(t, err)
		if string(payload) != "test" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
		}
		err = RemoveKey(rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Encrypt/Decrypt: Cipher_RSA_PADDING_OAEP_SHA256", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(keystore)
		assert.NoError(t, err)
		cipherEncrypt, err := NewCipher(kms.Encrypt, rsaKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_RSA_PADDING_OAEP_SHA256,
		})
		assert.NoError(t, err)
		update, err := cipherEncrypt.Update([]byte("te"))
		if update == nil {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
		}
		if string(update) != "te" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
		}
		assert.NoError(t, err)
		encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
		assert.NoError(t, err)

		decryptCipher, err := NewCipher(kms.Decrypt, rsaKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_RSA_PADDING_OAEP_SHA256,
			IV:        iv,
			MAC:       mac,
		})
		payload, _, _, err := decryptCipher.Close(encryptedPayload)
		assert.NoError(t, err)
		if string(payload) != "test" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
		}
		err = RemoveKey(rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Encrypt/Decrypt: Cipher_RSA_PADDING_OAEP_SHA384", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(keystore)
		assert.NoError(t, err)
		cipherEncrypt, err := NewCipher(kms.Encrypt, rsaKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_RSA_PADDING_OAEP_SHA384,
		})
		assert.NoError(t, err)
		update, err := cipherEncrypt.Update([]byte("te"))
		if update == nil {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
		}
		if string(update) != "te" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
		}
		assert.NoError(t, err)
		encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
		assert.NoError(t, err)

		decryptCipher, err := NewCipher(kms.Decrypt, rsaKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_RSA_PADDING_OAEP_SHA384,
			IV:        iv,
			MAC:       mac,
		})
		payload, _, _, err := decryptCipher.Close(encryptedPayload)
		assert.NoError(t, err)
		if string(payload) != "test" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
		}
		err = RemoveKey(rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Encrypt/Decrypt: Cipher_RSA_PADDING_OAEP_SHA512", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(keystore)
		assert.NoError(t, err)
		cipherEncrypt, err := NewCipher(kms.Encrypt, rsaKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_RSA_PADDING_OAEP_SHA512,
		})
		assert.NoError(t, err)
		update, err := cipherEncrypt.Update([]byte("te"))
		if update == nil {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
		}
		if string(update) != "te" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
		}
		assert.NoError(t, err)
		encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
		assert.NoError(t, err)

		decryptCipher, err := NewCipher(kms.Decrypt, rsaKey, &kms.CipherParameters{
			Algorithm: kms.Cipher_RSA_PADDING_OAEP_SHA512,
			IV:        iv,
			MAC:       mac,
		})
		payload, _, _, err := decryptCipher.Close(encryptedPayload)
		assert.NoError(t, err)
		if string(payload) != "test" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
		}
		err = RemoveKey(rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA224_RSA_PKCS1_PSS", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(rsaKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA224_RSA_PKCS1_PSS,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(rsaKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA224_RSA_PKCS1_PSS,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA256_RSA_PKCS1_PSS", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(rsaKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA256_RSA_PKCS1_PSS,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(rsaKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA256_RSA_PKCS1_PSS,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA384_RSA_PKCS1_PSS", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(rsaKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA384_RSA_PKCS1_PSS,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(rsaKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA384_RSA_PKCS1_PSS,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA512_RSA_PKCS1_PSS", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(rsaKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA512_RSA_PKCS1_PSS,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(rsaKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA512_RSA_PKCS1_PSS,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA224_RSA", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(rsaKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA224_RSA,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(rsaKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA224_RSA,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA256_RSA", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(rsaKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA256_RSA,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(rsaKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA256_RSA,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA384_RSA", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(rsaKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA384_RSA,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(rsaKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA384_RSA,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA512_RSA", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(rsaKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA512_RSA,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(rsaKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA512_RSA,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA1_ECDSA", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		ecKey, err := GenerateTestKeyEC(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(ecKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA1_ECDSA,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(ecKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA1_ECDSA,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ecKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA224_ECDSA", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		ecKey, err := GenerateTestKeyEC(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(ecKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA224_ECDSA,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(ecKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA224_ECDSA,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ecKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA256_ECDSA", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		ecKey, err := GenerateTestKeyEC(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(ecKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA256_ECDSA,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(ecKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA256_ECDSA,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ecKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA384_ECDSA", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		ecKey, err := GenerateTestKeyEC(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(ecKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA384_ECDSA,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(ecKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA384_ECDSA,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ecKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA512_ECDSA", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		ecKey, err := GenerateTestKeyEC(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(ecKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA512_ECDSA,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(ecKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA512_ECDSA,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ecKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA3224_ECDSA", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		ecKey, err := GenerateTestKeyEC(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(ecKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA3224_ECDSA,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(ecKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA3224_ECDSA,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ecKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA3256_ECDSA", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		ecKey, err := GenerateTestKeyEC(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(ecKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA3256_ECDSA,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(ecKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA3256_ECDSA,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ecKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA3384_ECDSA", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		ecKey, err := GenerateTestKeyEC(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(ecKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA3384_ECDSA,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(ecKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA3384_ECDSA,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ecKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA3512_ECDSA", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		ecKey, err := GenerateTestKeyEC(keystore)
		assert.NoError(t, err)
		signer, err := NewSigner(ecKey, &kms.SignerParameters{
			Algorithm: kms.Sign_SHA3512_ECDSA,
		})
		assert.NoError(t, err)
		err = signer.Update([]byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close([]byte("st"))
		assert.NoError(t, err)

		verifier, err := NewVerifier(ecKey, &kms.VerifierParameters{
			Algorithm: kms.Sign_SHA3512_ECDSA,
			Signature: signature,
		})
		err = verifier.Update([]byte("te"))
		assert.NoError(t, err)
		err = verifier.Close([]byte("st"))
		assert.NoError(t, err)
		err = verifier.CloseEx([]byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ecKey, keystore)
		assert.NoError(t, err)

	})
}
