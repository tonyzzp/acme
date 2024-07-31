package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
)

type JWK struct {
	Alg        string `json:"alg,omitempty"`
	Crv        string `json:"crv"`
	D          string `json:"d,omitempty"`
	Kty        string `json:"kty"`
	X          string `json:"x"`
	Y          string `json:"y"`
	privateKey *ecdsa.PrivateKey
}

func (jwk *JWK) PrivateKey() *ecdsa.PrivateKey {
	if jwk.privateKey != nil {
		return jwk.privateKey
	}
	pk := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     base64ToBigInt(jwk.X),
			Y:     base64ToBigInt(jwk.Y),
		},
		D: base64ToBigInt(jwk.D),
	}
	jwk.privateKey = pk
	return pk
}

func (jwk *JWK) sign(data string) (string, error) {
	pk := jwk.PrivateKey()
	sum := sha256.Sum256([]byte(data))
	r, s, e := ecdsa.Sign(rand.Reader, pk, sum[:])
	if e != nil {
		log.Println("sign")
		log.Println(e)
		return "", e
	}
	bs := append(r.Bytes(), s.Bytes()...)
	return base64.RawURLEncoding.EncodeToString(bs), nil
}

func (jwk *JWK) Encode() string {
	return fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, jwk.Crv, jwk.Kty, jwk.X, jwk.Y)
}

func NewECDSA() *JWK {
	pk, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		panic(e)
	}

	x := pk.PublicKey.X.Bytes()
	y := pk.PublicKey.Y.Bytes()
	d := pk.D.Bytes()

	jwk := &JWK{
		Kty: "EC",
		D:   base64.RawURLEncoding.EncodeToString(d),
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
		Alg: "ES256",
	}
	return jwk
}
