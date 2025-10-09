// Copyright (c) 2025 Securosys SA.

package securosyshsm

import (
	"context"
	"encoding/json"

	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/client"
	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure KeyStore implements KeyStore
var _ kms.Key = (*key)(nil)

type key struct {
	key      helpers.KeyAttributes
	client   *client.SecurosysClient
	password string
}

func (k key) IsAsymmetric() bool {
	if k.key.PublicKey != "" {
		return true
	}
	return false
}

func (k key) Resolved() bool {
	return true
}

func (k key) Resolve(ctx context.Context) (kms.Key, error) {
	return k, nil
}

func (k key) Login(ctx context.Context, credentials *kms.Credentials) error {
	if credentials != nil {
		k.password = credentials.Password
	}
	return nil
}

func (k key) GetType() kms.KeyType {
	switch k.key.Algorithm {
	case "RSA":
		return kms.KeyType_RSA_Private
	case "AES":
		return kms.KeyType_AES
	case "EC":
		return kms.KeyType_EC_Private
	case "ED":
		return kms.KeyType_ED_Private
	}
	return kms.Keytype_Unsupported
}

func (k key) GetProtectedKeyAttributes() *kms.ProtectedKeyAttributes {
	//TODO implement me
	panic("implement me")
}

func (s key) Close(ctx context.Context) error {
	s.password = ""
	return nil

}

func (s key) GetId() string {
	if s.key.Id != nil {
		return *s.key.Id
	}
	return s.key.Label
}

func (s key) GetName() string {
	return s.key.Label
}

func (s key) GetGroupId() string {
	return ""
}

func (s key) IsPersistent() bool {
	//TODO implement me
	panic("implement me")
}

func (s key) IsSensitive() bool {
	return s.key.Attributes["sensitive"]
}

func (s key) GetLength() uint32 {
	return uint32(s.key.KeySize)
}

func (s key) GetAlgorithm() string {
	if s.key.CurveOid != "" {
		return s.key.CurveOid
	}
	return s.key.AlgorithmOid
}

func (s key) GetKeyAttributes() *kms.KeyAttributes {
	attributes := s.key.Attributes

	keyAttributes := kms.KeyAttributes{
		Curve:            helpers.MapStringCurverToCurve(s.key.CurveOid),
		IsSensitive:      attributes["sensitive"],
		IsDerivable:      attributes["derive"],
		IsExportable:     attributes["extractable"],
		IsRemovable:      attributes["destroyable"],
		CanDecrypt:       attributes["decrypt"],
		CanEncrypt:       attributes["encrypt"],
		CanDerive:        attributes["derive"],
		CanSign:          attributes["sign"],
		CanVerify:        attributes["sign"],
		CanUnwrap:        attributes["unwrap"],
		CanWrap:          attributes["unwrap"],
		ProviderSpecific: convertPolicyToMap(s.key.Policy),
	}
	return &keyAttributes
}
func convertPolicyToMap(policy *helpers.Policy) map[string]interface{} {
	if policy == nil {
		return nil
	}
	// Convert struct -> JSON bytes
	data, _ := json.Marshal(policy)

	// Convert JSON bytes -> map[string]interface{}
	var result map[string]interface{}
	err := json.Unmarshal(data, &result)
	if err != nil {
		return nil
	}
	return result
}
