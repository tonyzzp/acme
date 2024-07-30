package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

type NewAccountProtected struct {
	Alg   string `json:"alg"`
	Jwk   JWK    `json:"jwk"`
	Nonce string `json:"nonce"`
	Url   string `json:"url"`
}

type NewAccountPayload struct {
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	Contact              []string `json:"contact"`
}

type NewAccountReq struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
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

		jwk := &JWK{
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

func newAccount(directory *AcmeDirectory, jwk *JWK) {

	pk := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     base64ToBigInt(jwk.X),
			Y:     base64ToBigInt(jwk.Y),
		},
		D: base64ToBigInt(jwk.D),
	}
	nonce := newNonce(directory)

	protected := NewAccountProtected{
		Alg: jwk.Alg,
		// Jwk: json.RawMessage(fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, jwk.Crv, jwk.Kty, jwk.X, jwk.Y)),
		// Jwk:   json.RawMessage(jwkEncode(&pk.PublicKey)),
		Jwk: JWK{
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

	req := NewAccountReq{
		Protected: base64Json(protected),
		Payload:   base64Json(payload),
	}
	// req.Signature = sign(pk, req.Protected+"."+req.Payload)
	// bs := sha256.Sum256([]byte(req.Protected + "." + req.Payload))
	// bs2, e := jwsSign(pk, crypto.SHA256, bs[:])
	// if e != nil {
	// 	fmt.Println(e)
	// 	os.Exit(-1)
	// }
	// req.Signature = base64.RawURLEncoding.EncodeToString(bs2[:])
	req.Signature = sign(pk, req.Protected+"."+req.Payload)
	log.Println("req")
	dumpJson(req)

	r := resty.New().R()
	r.Method = http.MethodPost
	r.SetBody(req)
	r.SetHeader("Content-Type", "application/jose+json")
	res, e := r.Post(directory.NewAccount)
	log.Println(e)
	log.Println(res.StatusCode(), res.Status())
	log.Println(string(res.Body()))
}

func main() {
	jwk := genJwk()
	f, e := os.OpenFile("log.log", os.O_CREATE, os.ModePerm)
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

	newAccount(directory, jwk)
}
