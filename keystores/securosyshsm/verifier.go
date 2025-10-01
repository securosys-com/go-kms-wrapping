// Copyright (c) 2025 Securosys SA.

package securosyshsm

import (
	b64 "encoding/base64"
	"errors"

	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure KeyStore implements KeyStore
var _ kms.Verifier = (*Verifier)(nil)

type Verifier struct {
	key            *Key
	verifierParams *kms.VerifierParameters
	buffer         []byte
}

func (s *Verifier) Update(data []byte) error {
	s.buffer = append(s.buffer, data...)
	return nil
}

func (s *Verifier) Close(data []byte) error {
	s.buffer = append(s.buffer, data...)
	return s.verifySignature(data, s.verifierParams.Signature)
}

func (s *Verifier) CloseEx(data []byte, signature []byte) error {
	s.buffer = append(s.buffer, data...)
	return s.verifySignature(data, signature)
}

func (s *Verifier) verifySignature(data []byte, signature []byte) error {
	signatureAlgorithm, _ := helpers.MapSignAlgorithm(s.verifierParams.Algorithm)
	result, _, err := s.key.client.Verify(
		s.key.GetName(),
		s.key.password,
		b64.StdEncoding.EncodeToString(s.buffer),
		signatureAlgorithm,
		b64.StdEncoding.EncodeToString(signature),
	)
	if err != nil {
		s.buffer = nil
		return err
	}
	s.buffer = nil
	if result == false {
		return errors.New("signature verification failed: provided signature is not valid")
	}
	return nil
}

// Ensure KeyStoreFactory implements KeyStoreFactory
var _ kms.VerifierFactory = (*VerifierFactory)(nil)

type VerifierFactory struct {
}

func (s VerifierFactory) NewVerifier(publicKey kms.Key, verifierParams *kms.VerifierParameters) (kms.Verifier, error) {
	if publicKey.GetType() != kms.PrivateRSAKey && publicKey.GetType() != kms.PrivateECKey {
		return nil, errors.New("invalid key type. Only RSA and EC keys are supported")
	}
	sk, ok := publicKey.(*Key)
	if !ok {
		return nil, errors.New("invalid key type: not Key")
	}
	return &Verifier{
		key:            sk,
		verifierParams: verifierParams,
	}, nil
}

func NewVerifier(publicKey kms.Key, verifierParams *kms.VerifierParameters) (kms.Verifier, error) {
	factory := &VerifierFactory{}
	return factory.NewVerifier(publicKey, verifierParams)
}
