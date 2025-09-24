/*
Copyright (c) 2023 Securosys SA, authors: Tomasz Madej, Mikolaj Szargut

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.
*/

package helpers

import (
	"encoding/json"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

// STRUCTS

// Structure for all asychnronous operations
type RequestResponse struct {
	Id               string   `json:"id"`
	Status           string   `json:"status"`
	ExecutionTime    string   `json:"executionTime"`
	ApprovedBy       []string `json:"approvedBy"`
	NotYetApprovedBy []string `json:"notYetApprovedBy"`
	RejectedBy       []string `json:"rejectedBy"`
	Result           string   `json:"result"`
}

// Structure for get key attributes response
type KeyAttributes struct {
	Id                 *string
	Label              string
	Attributes         map[string]bool
	KeySize            float64
	Policy             *kms.Policy
	DerivedAttributes  map[string]interface{}
	PublicKey          string
	Algorithm          string
	AlgorithmOid       string
	CurveOid           string
	Version            string
	Active             bool
	Xml                string
	XmlSignature       string
	AttestationKeyName string
}

// SecurosysConfig includes the minimum configuration
// required to instantiate a new HashiCups client.
type SecurosysConfig struct {
	Auth               string `json:"auth"`
	BearerToken        string `json:"bearertoken"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	BasicToken         string `json:"basictoken"`
	CertPath           string `json:"certpath"`
	KeyPath            string `json:"keypath"`
	RestApi            string `json:"restapi"`
	AppName            string `json:"appName"`
	ApplicationKeyPair string `json:"applicationKeyPair"`
	ApiKeys            string `json:"apiKeys"`
}

// Structure for certificate operations
type RequestResponseCertificate struct {
	Label       string `json:"label"`
	Certificate string `json:"certificate"`
}

// Structure for certificate operations
type RequestResponseImportCertificate struct {
	Label       string `json:"label"`
	Certificate string `json:"certificate"`
}

type GenerateCertificateRequest struct {
	// The same key id as passed in the request.
	KeyID        string            `json:"keyId"`
	PluginConfig map[string]string `json:"pluginConfig,omitempty"`
	Certificate  Certificate       `json:"certificate"`
}

type CertificateAttributes struct {
	CommonName           string  `json:"commonName"`
	Country              *string `json:"country"`
	StateOrProvinceName  *string `json:"stateOrProvinceName"`
	Locality             *string `json:"locality"`
	OrganizationName     *string `json:"organizationName"`
	OrganizationUnitName *string `json:"organizationUnitName"`
	Email                *string `json:"email"`
	Title                *string `json:"title"`
	Surname              *string `json:"surname"`
	GivenName            *string `json:"givenName"`
	Initials             *string `json:"initials"`
	Pseudonym            *string `json:"pseudonym"`
	GenerationQualifier  *string `json:"generationQualifier"`
}

func (ca *CertificateAttributes) ToString() string {
	respData := map[string]interface{}{
		"commonName":       ca.CommonName,
		"country":          ca.Country,
		"organizationName": ca.OrganizationName,
	}
	jsonStr, _ := json.Marshal(respData)
	return string(jsonStr[:])
}

type Certificate struct {
	Validity   int                   `json:"validity"`
	Attributes CertificateAttributes `json:"attributes"`
}

type ImportCertificateRequest struct {
	// The same key id as passed in the request.
	KeyID        string            `json:"keyId"`
	PluginConfig map[string]string `json:"pluginConfig,omitempty"`
}

type GenerateCertificateResponse struct {
	// The same key id as passed in the request.
	KeyID       string `json:"label"`
	Certificate string `json:"certificate"`
	KeyVersion  string `json:"keyVersion"`
}

type GenerateCertificateRequestResponse struct {
	// The same key id as passed in the request.
	KeyID              string `json:"label"`
	CertificateRequest string `json:"certificateSigningRequest"`
	KeyVersion         string `json:"keyVersion"`
}

type GenerateSelfSignedCertificateResponse struct {
	// The same key id as passed in the request.
	KeyID      string `json:"label"`
	KeyVersion string `json:"keyVersion"`

	CertificateRequest string `json:"certificate"`
}
type DecryptResponse struct {
	Payload string `json:"payload"`
}
type EncryptResponse struct {
	EncryptedPayload                                 string  `json:"encryptedPayload"`
	EncryptedPayloadWithoutMessageAuthenticationCode string  `json:"encryptedPayloadWithoutMessageAuthenticationCode"`
	InitializationVector                             *string `json:"initializationVector"`
	MessageAuthenticationCode                        *string `json:"messageAuthenticationCode"`
	KeyVersion                                       string  `json:"keyVersion"`
}
type SignatureResponse struct {
	Signature  string `json:"signature"`
	KeyVersion string `json:"keyVersion"`
}
type WrapResponse struct {
	WrappedKey string `json:"wrappedKey"`
	KeyVersion string `json:"keyVersion"`
}

//END STRUCTS
