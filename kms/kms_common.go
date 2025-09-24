// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

// Credentials provides login credentials for a keystore provider
// TODO
type Credentials struct {
	Username string
	Password string
}

type Approval struct {
	TypeOfKey string  `json:"type"`
	Name      *string `json:"name"`
	Value     *string `json:"value"`
}
type Group struct {
	Name      string     `json:"name"`
	Quorum    int        `json:"quorum"`
	Approvals []Approval `json:"approvals"`
}
type Token struct {
	Name     string  `json:"name"`
	Timelock int     `json:"timelock"`
	Timeout  int     `json:"timeout"`
	Groups   []Group `json:"groups"`
}
type Rule struct {
	Tokens []Token `json:"tokens"`
}
type KeyStatus struct {
	Blocked bool `json:"blocked"`
}

// Policy structure for rules use, block, unblock, modify
type Policy struct {
	RuleUse     Rule       `json:"ruleUse"`
	RuleBlock   *Rule      `json:"ruleBlock,omitempty"`
	RuleUnBlock *Rule      `json:"ruleUnblock,omitempty"`
	RuleModify  *Rule      `json:"ruleModify,omitempty"`
	KeyStatus   *KeyStatus `json:"keyStatus,omitempty"`
}

// Specific initialization parameters for the current crypto provider.
type CryptoProviderParameters struct {
	KeystoreProvider string
	Credentials      *Credentials
	// SECUROSYS PROPORSAL
	Params map[string]interface{}
	// TODO: define opaque parameters specific to each crypto provider (or derive specific structure from this).
}
