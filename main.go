package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/go-resty/resty/v2"
)

type JWK struct {
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv"`
	D   string `json:"d,omitempty"`
	Kid string `json:"kid,omitempty"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (jwk *JWK) key() *ecdsa.PrivateKey {
	pk := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     base64ToBigInt(jwk.X),
			Y:     base64ToBigInt(jwk.Y),
		},
		D: base64ToBigInt(jwk.D),
	}
	return pk
}

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

type Protected struct {
	Alg   string `json:"alg"`
	Kid   string `json:"kid,omitempty"`
	Jwk   *JWK   `json:"jwk,omitempty"`
	Nonce string `json:"nonce"`
	Url   string `json:"url"`
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

type OrderIdentify struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type NewOrderPayload struct {
	Identifiers []OrderIdentify `json:"identifiers"`
	NotBefore   string          `json:"notBefore"`
	NotAfter    string          `json:"notAfter"`
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
	Status         string
	Expires        string
	Identifiers    []OrderIdentify
	Authorizations []string
	Finalize       string
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
}

type OrderInfo struct {
	Identifier OrderIdentify
	Status     string
	Expires    string
	Challenges []Challenge
}

func isSuccess(code int) bool {
	return code >= 200 && code < 300
}

func dumpJson(data any) {
	bs, e := json.MarshalIndent(data, "", "    ")
	if e != nil {
		log.Println(e)
		os.Exit(-1)
	}
	log.Println(string(bs))
}

func base64Json(data any) string {
	bs, e := json.Marshal(data)
	if e != nil {
		log.Println("base64Json", data)
		log.Println(e)
		os.Exit(-1)
	}
	return base64.RawURLEncoding.EncodeToString(bs)
}

func base64ToBigInt(s string) *big.Int {
	rtn := &big.Int{}
	bs, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil {
		log.Println(e)
		os.Exit(-1)
	}
	rtn.SetBytes(bs)
	return rtn
}

func genJwk() *JWK {
	var jwk = &JWK{}
	var file = "jwk.json"
	_, e := os.Stat(file)
	if e == nil {
		bs, e := os.ReadFile(file)
		if e != nil {
			log.Println(e)
			os.Exit(-1)
		}
		json.Unmarshal(bs, jwk)
	} else {
		pk, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		log.Println(e)
		log.Println(pk)

		x := pk.PublicKey.X.Bytes()
		y := pk.PublicKey.Y.Bytes()
		d := pk.D.Bytes()

		kid := sha256.Sum256([]byte(time.Now().String()))

		jwk = &JWK{
			Kty: "EC",
			D:   base64.RawURLEncoding.EncodeToString(d),
			Crv: "P-256",
			Kid: base64.RawURLEncoding.EncodeToString(kid[:]),
			X:   base64.RawURLEncoding.EncodeToString(x),
			Y:   base64.RawURLEncoding.EncodeToString(y),
			Alg: "ES256",
		}
		bs, e := json.MarshalIndent(jwk, "", "    ")
		log.Println(e)
		log.Println(string(bs))
		os.WriteFile("jwk.json", bs, os.ModePerm)
	}
	return jwk
}

func sign(pk *ecdsa.PrivateKey, data string) string {
	sum := sha256.Sum256([]byte(data))
	r, s, e := ecdsa.Sign(rand.Reader, pk, sum[:])
	if e != nil {
		log.Println("sign")
		log.Println(e)
		os.Exit(-1)
	}
	bs := append(r.Bytes(), s.Bytes()...)
	return base64.RawURLEncoding.EncodeToString(bs)
}

func getDirectory() *AcmeDirectory {
	rtn := &AcmeDirectory{}
	r := resty.New().R()
	r.SetResult(rtn)
	res, e := r.Get("https://acme-staging-v02.api.letsencrypt.org/directory")
	if e != nil {
		log.Println(e)
		log.Println(res.StatusCode())
		log.Println(res.Status())
		log.Println(string(res.Body()))
	}
	return rtn
}

func newNonce(director *AcmeDirectory) string {
	res, e := resty.New().R().Head(director.NewNonce)
	if e != nil {
		log.Println(e)
		os.Exit(-1)
	}
	return res.Header()["Replay-Nonce"][0]
}

func newAccount(directory *AcmeDirectory, jwk *JWK) *AcmeAccount {
	log.Println("------------------newAccount")
	pk := jwk.key()
	nonce := newNonce(directory)

	protected := Protected{
		Alg: jwk.Alg,
		Jwk: &JWK{
			Kid: jwk.Kid,
			Kty: jwk.Kty,
			Crv: jwk.Crv,
			X:   jwk.X,
			Y:   jwk.Y,
		},
		Nonce: nonce,
		Url:   directory.NewAccount,
	}
	log.Println("protected")
	dumpJson(protected)

	payload := NewAccountPayload{
		TermsOfServiceAgreed: true,
		Contact:              []string{"mailto:i@izzp.me"},
	}
	log.Println("payload")
	dumpJson(payload)

	req := Req{
		Protected: base64Json(protected),
		Payload:   base64Json(payload),
	}
	req.Signature = sign(pk, req.Protected+"."+req.Payload)
	log.Println("req")
	dumpJson(req)

	rtn := &AcmeAccount{}
	r := resty.New().R()
	r.Method = http.MethodPost
	r.SetBody(req)
	r.SetHeader("Content-Type", "application/jose+json")
	r.SetResult(rtn)
	res, e := r.Post(directory.NewAccount)
	if e != nil || res.StatusCode() != 200 {
		log.Println(e)
		log.Println(res.Status())
		log.Println(res.Header())
		log.Println(string(res.Body()))
		os.Exit(-1)
	} else {
		rtn.Kid = res.Header()["Location"][0]
	}
	return rtn
}

func newOrder(directory *AcmeDirectory, jwk *JWK, account *AcmeAccount) *Order {
	log.Println("----------------------------newOrder")
	pk := jwk.key()
	nonce := newNonce(directory)

	protected := Protected{
		Alg:   jwk.Alg,
		Kid:   account.Kid,
		Nonce: nonce,
		Url:   directory.NewOrder,
	}
	log.Println("protected")
	dumpJson(protected)

	payload := NewOrderPayload{
		Identifiers: []OrderIdentify{
			{
				Type:  "dns",
				Value: "test.izzp.me",
			},
		},
	}

	req := Req{
		Protected: base64Json(protected),
		Payload:   base64Json(payload),
	}
	req.Signature = sign(pk, req.Protected+"."+req.Payload)
	log.Println("req")
	dumpJson(req)

	rtn := &Order{}
	r := resty.New().R()
	r.Method = http.MethodPost
	r.SetHeader("Content-Type", "application/jose+json")
	r.SetBody(req)
	r.SetResult(rtn)
	res, e := r.Post(directory.NewOrder)
	if e != nil || !isSuccess(res.StatusCode()) {
		log.Println(e)
		log.Println(res.Status())
		log.Println(string(res.Body()))
		os.Exit(-1)
	}
	return rtn
}

func getOrderInfo(url string) *OrderInfo {
	log.Println("------------------getOrderInfo")
	rtn := &OrderInfo{}
	r := resty.New().R()
	r.SetResult(rtn)
	res, e := r.Get(url)
	if e != nil || !isSuccess(res.StatusCode()) {
		log.Println(e)
		log.Println(res.Header())
		log.Println(res.Header())
		log.Println(string(res.Body()))
		os.Exit(-1)
	}
	return rtn
}

func checkChallenge(url string) *Challenge {
	log.Println("------------------checkChallenge")
	rtn := &Challenge{}
	r := resty.New().R()
	r.SetResult(rtn)
	res, e := r.Get(url)
	if e != nil {
		log.Println(e)
		log.Println(string(res.Body()))
	}
	return rtn
}

func submitChallenge(directory *AcmeDirectory, challenge Challenge, jwk *JWK, account *AcmeAccount) {
	log.Println("----------------------------submitChallenge")
	pk := jwk.key()
	nonce := newNonce(directory)

	protected := Protected{
		Alg:   jwk.Alg,
		Kid:   account.Kid,
		Nonce: nonce,
		Url:   challenge.Url,
	}
	log.Println("protected")
	dumpJson(protected)

	req := Req{
		Protected: base64Json(protected),
		Payload:   base64Json(map[string]any{}),
	}
	req.Signature = sign(pk, req.Protected+"."+req.Payload)

	log.Println("req")
	dumpJson(req)

	r := resty.New().R()
	r.Method = http.MethodPost
	r.SetHeader("Content-Type", "application/jose+json")
	r.SetBody(req)
	res, e := r.Post(challenge.Url)
	log.Println(e)
	if res != nil {
		log.Println(res.Status())
		log.Println(string(res.Body()))
	}
}

func main() {
	jwk := genJwk()
	f, e := os.OpenFile("log.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if e != nil {
		println(e)
		os.Exit(-1)
	}
	log.SetOutput(io.MultiWriter(os.Stdout, f))
	log.SetFlags(0)
	log.Println("jwk")
	dumpJson(jwk)
	directory := getDirectory()
	log.Println("directory")
	dumpJson(directory)

	account := newAccount(directory, jwk)
	log.Println("account")
	dumpJson(account)

	order := newOrder(directory, jwk, account)
	log.Println("order")
	dumpJson(order)

	orderInfo := getOrderInfo(order.Authorizations[0])
	log.Println("orderInfo")
	dumpJson(orderInfo)

	var challenge *Challenge
	for _, v := range orderInfo.Challenges {
		if v.Type == "dns-01" {
			challenge = &v
			break
		}
	}
	log.Println("challenge")
	dumpJson(challenge)

	challenge = checkChallenge(challenge.Url)
	log.Println("check challenge")
	dumpJson(challenge)

	if challenge.Status == "pending" {
		log.Println("token", challenge.Token)
		log.Println("press y after dns setted")
		ok := ""
		fmt.Scanf("%s\n", &ok)
		log.Println("ok", ok)
		if ok != "y" {
			os.Exit(-1)
		}
	}

	challenge = checkChallenge(challenge.Url)
	log.Println("check challenge")
	dumpJson(challenge)

	submitChallenge(directory, *challenge, jwk, account)
}
