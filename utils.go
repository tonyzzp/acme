package acme

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"os"
)

func dumpJson(data any) {
	bs, e := json.MarshalIndent(data, "", "    ")
	if e != nil {
		log.Println(e)
	} else {
		log.Println(string(bs))
	}
}

func base64Json(data any) (string, error) {
	bs, e := json.Marshal(data)
	if e != nil {
		log.Println("base64Json", data)
		log.Println(e)
		return "", nil
	}
	return base64.RawURLEncoding.EncodeToString(bs), nil
}

func mustBase64Json(data any) string {
	rtn, e := base64Json(data)
	if e != nil {
		panic("base64json failed")
	}
	return rtn
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

func writeJson(file string, data any) error {
	bs, e := json.MarshalIndent(data, "", "    ")
	if e != nil {
		return e
	}
	e = os.WriteFile(file, bs, os.ModePerm)
	return e
}

func convertPkToPEM(pk *ecdsa.PrivateKey) ([]byte, error) {
	bs, e := x509.MarshalECPrivateKey(pk)
	if e != nil {
		return nil, e
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: bs,
	}
	bs = pem.EncodeToMemory(block)
	return bs, nil
}
