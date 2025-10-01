// Copyright (c) 2025 Securosys SA.

package securosyshsm

import (
	b64 "encoding/base64"
	"errors"
	"time"

	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure KeyStore implements KeyStore
var _ kms.Signer = (*Signer)(nil)

type Signer struct {
	key          *Key
	signerParams *kms.SignerParameters
	buffer       []byte
}

func (s *Signer) Update(data []byte) error {
	s.buffer = append(s.buffer, data...)
	return nil
}

func (s *Signer) Close(data []byte) (signature []byte, err error) {
	s.buffer = append(s.buffer, data...)
	return s.Sign()
}
func (s *Signer) Sign() ([]byte, error) {
	signatureAlgorithm, _ := helpers.MapSignAlgorithm(s.signerParams.Algorithm)
	result, _, err := s.key.client.AsyncSign(
		s.key.GetName(),
		s.key.password,
		b64.StdEncoding.EncodeToString(s.buffer),
		"UNSPECIFIED",
		signatureAlgorithm,
		map[string]string{},
	)
	if err != nil {
		s.buffer = nil
		return nil, err
	}

	request, _, err := s.key.client.GetRequest(result)
	for request.Status == "PENDING" {
		if err != nil {
			s.buffer = nil
			return nil, err
		}
		time.Sleep(5 * time.Second)
		request, _, err = s.key.client.GetRequest(result)
	}
	if request.Status != "EXECUTED" {
		s.buffer = nil
		return nil, errors.New("Signer failed to execute. Signer returned status: " + request.Status)
	}
	s.buffer = nil
	signature, _ := b64.StdEncoding.DecodeString(request.Result)
	return signature, nil
}

type SignerFactory struct {
}

// Ensure KeyStoreFactory implements KeyStoreFactory
var _ kms.SignerFactory = (*SignerFactory)(nil)

func (s SignerFactory) NewSigner(privateKey kms.Key, signerParams *kms.SignerParameters) (kms.Signer, error) {
	if privateKey.GetType() != kms.PrivateRSAKey && privateKey.GetType() != kms.PrivateECKey {
		return nil, errors.New("invalid key type. Only RSA and EC keys are supported")
	}
	sk, ok := privateKey.(*Key)
	if !ok {
		return nil, errors.New("invalid key type: not Key")
	}
	return &Signer{
		key:          sk,
		signerParams: signerParams,
	}, nil
}

func NewSigner(privateKey kms.Key, signerParams *kms.SignerParameters) (kms.Signer, error) {
	factory := &SignerFactory{}
	return factory.NewSigner(privateKey, signerParams)
}
