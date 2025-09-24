module github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2

replace github.com/openbao/go-kms-wrapping/v2 => ../../

go 1.24.0

require github.com/openbao/go-kms-wrapping/v2 v2.5.0

require (
	github.com/hashicorp/go-secure-stdlib/parseutil v0.2.0 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.7 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	google.golang.org/protobuf v1.36.9 // indirect
)
