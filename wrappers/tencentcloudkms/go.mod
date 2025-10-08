module github.com/openbao/go-kms-wrapping/wrappers/tencentcloudkms/v2

go 1.25.0

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/openbao/go-kms-wrapping/v2 v2.2.0
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common v1.0.604
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/kms v1.0.604
)

require (
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.9 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.6 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	google.golang.org/protobuf v1.36.4 // indirect
)

retract [v2.0.0, v2.0.1]
