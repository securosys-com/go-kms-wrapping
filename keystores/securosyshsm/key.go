// Copyright (c) 2025 Securosys SA.

package securosyshsm

import (
	"fmt"

	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/client"
	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure KeyStore implements KeyStore
var _ kms.Key = (*Key)(nil)

type Key struct {
	key      helpers.KeyAttributes
	client   *client.SecurosysClient
	password string
}

func (s Key) GetPolicy() *kms.Policy {

	return s.key.Policy
}

func (s Key) Close() error {
	s.password = ""
	return nil

}
func (s Key) String() string {
	// Only print relevant fields
	return fmt.Sprintf("%s | %v | %d ", s.GetName(), s.GetType(), s.GetLength())
}

func (s Key) Login(credentials *kms.Credentials) error {
	if credentials != nil {
		s.password = credentials.Password
	}
	return nil
}

func (s Key) GetType() kms.KeyType {
	switch s.key.Algorithm {
	case "RSA":
		return kms.PrivateRSAKey
	case "AES":
		return kms.AESKey
	case "EC":
		return kms.PrivateECKey
	}
	return kms.UnSupportedKey
}

func (s Key) GetId() string {
	if s.key.Id != nil {
		return *s.key.Id
	}
	return s.key.Label
}

func (s Key) GetName() string {
	return s.key.Label
}

func (s Key) GetGroupId() string {
	return ""
}

func (s Key) IsPersistent() bool {
	//TODO implement me
	panic("implement me")
}

func (s Key) IsSensitive() bool {
	return s.key.Attributes["sensitive"]
}

func (s Key) GetLength() uint32 {
	return uint32(s.key.KeySize)
}

func (s Key) GetAlgorithm() string {
	if s.key.CurveOid != "" {
		return s.key.CurveOid
	}
	return s.key.AlgorithmOid
}

func (s Key) GetKeyAttributes() *kms.KeyAttributes {
	attributes := s.key.Attributes
	keyAttributes := kms.KeyAttributes{
		IsSensitive:  attributes["sensitive"],
		IsDerivable:  attributes["derive"],
		IsExportable: attributes["extractable"],
		IsRemovable:  attributes["destroyable"],
		CanDecrypt:   attributes["decrypt"],
		CanEncrypt:   attributes["encrypt"],
		CanDerive:    attributes["derive"],
		CanSign:      attributes["sign"],
		CanVerify:    attributes["sign"],
		CanUnwrap:    attributes["unwrap"],
		CanWrap:      attributes["unwrap"],
	}
	return &keyAttributes
}
