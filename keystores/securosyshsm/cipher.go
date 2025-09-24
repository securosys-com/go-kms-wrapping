package securosyshsm

import (
	b64 "encoding/base64"
	"errors"

	kms "github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure KeyStore implements KeyStore
var _ kms.Cipher = (*Cipher)(nil)

type Cipher struct {
	operation    kms.CipherOperation
	key          *Key
	cipherParams *kms.CipherParameters
	buffer       []byte
}

func (s Cipher) Update(inputData []byte) (outputData []byte, err error) {
	// Just buffer the input
	s.buffer = append(s.buffer, inputData...)
	return nil, nil // nothing processed yet
}

func (s Cipher) Close(inputData []byte) (outputData []byte, iv []byte, mac []byte, err error) {
	s.buffer = append(s.buffer, inputData...)
	algorithm := s.cipherParams.Algorithm
	cipherAlgorithm := ""
	switch algorithm {
	case kms.Cipher_AES_GCM:
		cipherAlgorithm = "AES_GCM"
	}
	//Only Support AES encrypt/decrypt
	if s.operation == kms.Decrypt {
		return s.Decrypt(cipherAlgorithm)
	} else {
		return s.Encrypt(cipherAlgorithm)
	}
}
func (s Cipher) Decrypt(cipherAlgorithm string) (outputData []byte, iv []byte, mac []byte, err error) {
	tagLength := len(s.cipherParams.MAC) * 8
	decrypt, _, err := s.key.client.Decrypt(
		s.key.GetName(),
		s.key.password,
		b64.StdEncoding.EncodeToString(append(s.buffer, s.cipherParams.MAC...)),
		b64.StdEncoding.EncodeToString(s.cipherParams.IV),
		cipherAlgorithm,
		tagLength,
		b64.StdEncoding.EncodeToString(s.cipherParams.AAD),
	)
	if err != nil {
		s.buffer = nil
		return nil, nil, nil, err
	}
	data, err := b64.StdEncoding.DecodeString(decrypt.Payload)
	if err != nil {
		s.buffer = nil
		return nil, nil, nil, err
	}
	s.buffer = nil
	return data, nil, nil, nil

}
func (s Cipher) Encrypt(cipherAlgorithm string) (outputData []byte, iv []byte, mac []byte, err error) {
	encrypt, _, err := s.key.client.Encrypt(
		s.key.GetName(),
		s.key.password,
		b64.StdEncoding.EncodeToString(s.buffer),
		cipherAlgorithm,
		128,
		b64.StdEncoding.EncodeToString(s.cipherParams.AAD),
	)
	if err != nil {
		s.buffer = nil
		return nil, nil, nil, err
	}
	encryptedPayload, _ := b64.StdEncoding.DecodeString(encrypt.EncryptedPayloadWithoutMessageAuthenticationCode)
	var initializationVector []byte
	if encrypt.InitializationVector != nil {
		initializationVector, _ = b64.StdEncoding.DecodeString(*encrypt.InitializationVector)
	}
	var messageAuthenticationCode []byte

	if encrypt.MessageAuthenticationCode != nil {
		messageAuthenticationCode, _ = b64.StdEncoding.DecodeString(*encrypt.MessageAuthenticationCode)
	}
	s.buffer = nil
	return encryptedPayload, initializationVector, messageAuthenticationCode, nil

}

type CipherFactory struct {
}

// Ensure KeyStoreFactory implements KeyStoreFactory
var _ kms.CipherFactory = (*CipherFactory)(nil)

func (s CipherFactory) NewCipher(operation kms.CipherOperation, key kms.Key, cipherParams *kms.CipherParameters) (kms.Cipher, error) {
	if key.GetType() != kms.AESKey {
		return nil, errors.New("invalid key type. Only AES keys are supported")
	}
	sk, ok := key.(*Key)
	if !ok {
		return nil, errors.New("invalid key type: not Key")
	}
	return &Cipher{
		operation:    operation,
		key:          sk,
		cipherParams: cipherParams,
	}, nil

}
func NewCipher(operation kms.CipherOperation, key kms.Key, cipherParams *kms.CipherParameters) (kms.Cipher, error) {
	factory := &CipherFactory{}
	return factory.NewCipher(operation, key, cipherParams)
}
