package acme

type AcmeDirectory struct {
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

type HeaderJWK struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type Protected struct {
	Alg   string     `json:"alg"`
	Kid   string     `json:"kid,omitempty"`
	Jwk   *HeaderJWK `json:"jwk,omitempty"`
	Nonce string     `json:"nonce"`
	Url   string     `json:"url"`
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

type AcmeAccount struct {
	Kid       string
	Key       JWK
	Contact   []string
	InitialIp string
	CreatedAt string
	Status    string
}

type Order struct {
	Url            string
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

type OrderInfo struct {
	Identifier Identifier
	Status     string
	Expires    string
	Challenges []Challenge
}

type HttpRequestParam struct {
	Url     string
	Method  string
	Kid     string
	Payload any
	Result  any
}

type CSRPayload struct {
	Csr string `json:"csr"`
}
