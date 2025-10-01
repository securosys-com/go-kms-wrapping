// Copyright (c) 2025 Securosys SA.

package securosyshsm

import (
	b64 "encoding/base64"
	"errors"
	"time"

	"github.com/andreburgaud/crypt2go/padding"
	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
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

func (s *Cipher) Update(inputData []byte) (outputData []byte, err error) {
	// Just buffer the input
	s.buffer = append(s.buffer, inputData...)
	return s.buffer, nil // nothing processed yet
}

func (s *Cipher) Close(inputData []byte) (outputData []byte, iv []byte, mac []byte, err error) {
	s.buffer = append(s.buffer, inputData...)
	algorithm := s.cipherParams.Algorithm
	cipherAlgorithm, err := helpers.MapCipherAlgorithm(algorithm)
	if err != nil {
		return nil, nil, nil, err
	}
	//Only Support AES encrypt/decrypt
	if s.operation == kms.Decrypt {
		payload, iv, mac, err := s.Decrypt(cipherAlgorithm)
		return s.RemovePaddingIfNeeded(payload), iv, mac, err
	} else {
		s.AddPaddingIfNeeded()
		return s.Encrypt(cipherAlgorithm)
	}
}

func (s Cipher) DecryptAsyncRequest(additionalMetaData map[string]string) (string, error) {
	tagLength := 0
	encryptedPayload := s.buffer
	vector := ""
	aad := ""
	algorithm := s.cipherParams.Algorithm
	cipherAlgorithm, err := helpers.MapCipherAlgorithm(algorithm)
	if err != nil {
		return "", err
	}

	result, _, err := s.key.client.AsyncDecrypt(
		s.key.GetName(),
		s.key.password,
		b64.StdEncoding.EncodeToString(encryptedPayload),
		vector,
		cipherAlgorithm,
		tagLength,
		aad,
		additionalMetaData,
	)
	return result, err
}
func (s Cipher) GetRequest(requestId string) (*helpers.RequestResponse, error) {
	request, _, err := s.key.client.GetRequest(requestId)
	return request, err
}

func (s *Cipher) Decrypt(cipherAlgorithm string) (outputData []byte, iv []byte, mac []byte, err error) {
	tagLength := 0
	encryptedPayload := s.buffer
	if s.cipherParams.MAC != nil {
		tagLength = len(s.cipherParams.MAC) * 8
		encryptedPayload = append(encryptedPayload, s.cipherParams.MAC...)
	}
	vector := ""
	if s.cipherParams.IV != nil {
		vector = b64.StdEncoding.EncodeToString(s.cipherParams.IV)
	}
	aad := ""
	if s.cipherParams.AAD != nil {
		aad = b64.StdEncoding.EncodeToString(s.cipherParams.AAD)
	}

	result, _, err := s.key.client.AsyncDecrypt(
		s.key.GetName(),
		s.key.password,
		b64.StdEncoding.EncodeToString(encryptedPayload),
		vector,
		cipherAlgorithm,
		tagLength,
		aad,
		make(map[string]string),
	)
	request, _, err := s.key.client.GetRequest(result)
	for request.Status == "PENDING" {
		if err != nil {
			s.buffer = nil
			return nil, nil, nil, err
		}
		time.Sleep(5 * time.Second)
		request, _, err = s.key.client.GetRequest(result)
	}
	if request.Status != "EXECUTED" {
		s.buffer = nil
		return nil, nil, nil, errors.New("Decrypt failed to execute. Decrypt returned status: " + request.Status)
	}
	s.buffer = nil
	payload, _ := b64.StdEncoding.DecodeString(request.Result)

	return payload, nil, nil, nil

}
func (s *Cipher) RemovePaddingIfNeeded(payload []byte) []byte {
	if s.key.GetType() == kms.AESKey {
		switch s.cipherParams.Algorithm {
		case kms.Cipher_AES_ECB:
			padder := padding.NewPkcs7Padding(16)
			payload, _ := padder.Unpad(payload)
			return payload
		case kms.Cipher_AES_CBC:
			//case kms.Cipher_AES_CTR:
			padder := padding.NewPkcs7Padding(16)
			payload, _ := padder.Unpad(payload)
			return payload
		}

	}
	return payload

}
func (s *Cipher) AddPaddingIfNeeded() {
	if s.key.GetType() == kms.AESKey {
		switch s.cipherParams.Algorithm {
		case kms.Cipher_AES_ECB:
			padder := padding.NewPkcs7Padding(16)
			s.buffer, _ = padder.Pad(s.buffer)
			break
		case kms.Cipher_AES_CBC:
			//case kms.Cipher_AES_CTR:
			padder := padding.NewPkcs7Padding(16)
			s.buffer, _ = padder.Pad(s.buffer)
			break
		}

	}

}
func (s *Cipher) Encrypt(cipherAlgorithm string) (outputData []byte, iv []byte, mac []byte, err error) {
	aad := ""
	if s.cipherParams.AAD != nil {
		aad = b64.StdEncoding.EncodeToString(s.cipherParams.AAD)
	}
	tagLength := 0
	if s.cipherParams.Algorithm == kms.Cipher_AES_GCM {
		tagLength = 128
	} else {
		tagLength = -1
	}
	encrypt, _, err := s.key.client.Encrypt(
		s.key.GetName(),
		s.key.password,
		b64.StdEncoding.EncodeToString(s.buffer),
		cipherAlgorithm,
		tagLength,
		aad,
	)
	if err != nil {
		s.buffer = nil
		return nil, nil, nil, err
	}
	var encryptedPayload []byte
	if encrypt.EncryptedPayloadWithoutMessageAuthenticationCode == "" {
		encryptedPayload, _ = b64.StdEncoding.DecodeString(encrypt.EncryptedPayload)
	} else {
		encryptedPayload, _ = b64.StdEncoding.DecodeString(encrypt.EncryptedPayloadWithoutMessageAuthenticationCode)

	}

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
