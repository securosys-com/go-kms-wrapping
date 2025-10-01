// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

// CipherOperation represents the direction of the cipher operation: encrypt or decrypt.
type CipherOperation int

const (
	Encrypt CipherOperation = iota
	Decrypt
)

// CipherAlgorithm represents ciphering algorithms
type CipherAlgorithm string

const (
	Cipher_AES CipherAlgorithm = "aes"
	Cipher_RSA CipherAlgorithm = "rsa"
)

// CipherAlgorithmMode represents a combination between a cipher algorithm
// and a block mode.

type CipherAlgorithmMode int

const (
	// Unsafe cipher modes have been disabled until such time as required.
	Cipher_AES_ECB CipherAlgorithmMode = iota
	Cipher_AES_CBC
	Cipher_AES_CTR
	Cipher_AES_GCM // 3
	Cipher_RSA_MODE
	Cipher_RSA_PADDING_OAEP
	Cipher_RSA_PADDING_OAEP_SHA1
	Cipher_RSA_PADDING_OAEP_SHA224
	Cipher_RSA_PADDING_OAEP_SHA256
	Cipher_RSA_PADDING_OAEP_SHA384
	Cipher_RSA_PADDING_OAEP_SHA512
)

// Padding represents the padding required by some ciphering algorithms.
type Padding int

const (
	NoPadding Padding = iota
	
	// PKCS5Padding has been disabled as it is not required by AES-GCM mode.
	// PKCS5Padding Padding = iota
)

// CipherParameters defines the parameters required by a ciphering operation.
// We might want to specialize this per algorithm (provide CTR counter length, 64 bits, for example, etc.).
type CipherParameters struct {
	Algorithm CipherAlgorithmMode
	// Not every cipher algorithm requires padding.
	Padding Padding
	// Note: for encryption operations, the caller should not provide the  IV. Instead, the Cipher will generate a random IV.
	IV []byte
	// Additional authenticated data, when supported by the algorithm
	AAD []byte
	// MAC (Authentication Tag) of AEAD algorithms to be provided by the caller for decrypt operations.
	MAC []byte
}

// Cipher interface represents ciphering operations
type Cipher interface {
	// This function performs/continues a multiple-part ciphering operation, processing another data part.
	Update(inputData []byte) (outputData []byte, err error)

	// This function finishes a single or multiple-part ciphering operation, possibly processing the last data part.
	// Note: for encryption operations, the caller should not provide the IV when initalizating the Cipher.
	// Instead, the Cipher will generate a random IV that will be returned here.
	// The MAC (Authentication Tag) is returned by this function when encrypting with AEAD algorithms.
	Close(inputData []byte) (outputData []byte, iv []byte, mac []byte, err error)
}

// CipherFactory creates Cipher instances
type CipherFactory interface {
	// NewCipher creates a new Cipher instance
	NewCipher(operation CipherOperation, key Key, cipherParams *CipherParameters) (Cipher, error)
}
