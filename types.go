package acme

import (
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/tonyzzp/acme/utils"
)

type Directory struct {
	KeyChange   string
	NewAccount  string
	NewNonce    string
	NewOrder    string
	RenewalInfo string
	RevokeCert  string
	Meta        struct {
		CaaIdentities  []string
		TermsOfService string
		Website        string
	}
}

type Protected struct {
	Alg   string          `json:"alg"`
	Kid   string          `json:"kid,omitempty"`
	Jwk   json.RawMessage `json:"jwk,omitempty"`
	Nonce string          `json:"nonce"`
	Url   string          `json:"url"`
}

type NewAccountPayload struct {
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	Contact              []string `json:"contact"`
}

type Req struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type NewOrderPayload struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   string       `json:"notBefore"`
	NotAfter    string       `json:"notAfter"`
}

type Account struct {
	Uri                  string   `json:"uri"`
	Contact              []string `json:"contact"`
	InitialIp            string   `json:"initialIp"`
	CreatedAt            string   `json:"createdAt"`
	Status               string   `json:"status"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
}

type OrderList struct {
	Orders []string
}

const OrderStatusPending = "pending"
const OrderStatusProcessing = "processing"
const OrderStatusReady = "ready"
const OrderStatusValid = "valid"
const OrderStatusInvalid = "invalid"

type Order struct {
	Uri            string
	Status         string
	Expires        string
	NotBefore      string
	NotAfter       string
	Identifiers    []Identifier
	Authorizations []string
	Finalize       string
	Certificate    string
	RetryAfter     int
}

type Cert struct {
	Path          string
	FullChainPEM  string
	PrivateKeyPEM string
	JWK           *JWK
	Certs         []*x509.Certificate
}

func (order *Order) ShortDesc() string {
	id := utils.Md5String([]byte(order.Uri))
	id = id[:5]
	identifier := order.Identifiers[0]
	return fmt.Sprintf("%s %s %s %s", id, order.Status, identifier.Type, identifier.Value)
}

type Challenge struct {
	Type      string
	Url       string
	Status    string
	Token     string
	Validated string `json:"validated"`
	Error     struct {
		Type   string
		Detail string
		Status int
	}
	ValidationRecord []struct {
		Hostname string
	}
}

type Authorization struct {
	Status     string
	Expires    string
	Identifier Identifier
	Challenges []Challenge
	Wildcard   bool
}

type HttpRequestParam struct {
	Url     string
	Method  string
	Kid     string
	Payload any
	Result  any
}

type FinalizePayload struct {
	Csr string `json:"csr"`
}
