package acme

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/go-resty/resty/v2"
	"github.com/tonyzzp/acme/utils"
)

type AcmeClient struct {
	JWK         *JWK
	Directory   *AcmeDirectory
	Account     *AcmeAccount
	storeRoot   string
	storeCerts  string
	storeOrders string
}

func NewAcmeClient(store string) *AcmeClient {
	rtn := &AcmeClient{
		storeRoot:   store,
		storeOrders: filepath.Join(store, "orders"),
		storeCerts:  filepath.Join(store, "certs"),
	}
	return rtn
}

func (client *AcmeClient) InitKey() error {
	if client.JWK != nil {
		return nil
	}
	var jwk = &JWK{}
	var file = filepath.Join(client.storeRoot, "account.jwk.json")
	_, e := os.Stat(file)
	if e == nil {
		bs, e := os.ReadFile(file)
		if e != nil {
			log.Println(e)
			return e
		}
		e = json.Unmarshal(bs, jwk)
		if e != nil {
			return e
		}
	} else {
		jwk = NewECDSA()
		bs, e := json.MarshalIndent(jwk, "", "    ")
		if e != nil {
			log.Println(e)
			log.Println(string(bs))
			return e
		}
		e = os.WriteFile(file, bs, os.ModePerm)
		if e != nil {
			return e
		}
	}
	client.JWK = jwk
	return nil
}

func (client *AcmeClient) request(req HttpRequestParam) (*resty.Response, error) {
	log.Println("request")
	log.Println("req")
	DumpJson(req)
	e := client.InitKey()
	if e != nil {
		return nil, e
	}

	r := resty.New().R()
	r.Method = req.Method
	r.URL = req.Url
	if req.Method != "" && req.Method != http.MethodGet {
		r.SetHeader("Content-Type", "application/jose+json")
		nonce, e := client.newNonce()
		if e != nil {
			return nil, e
		}
		jwk := client.JWK
		protected := Protected{
			Alg:   jwk.Alg,
			Nonce: nonce,
			Url:   req.Url,
		}
		if req.Kid != "" {
			protected.Kid = req.Kid
		} else {
			protected.Jwk = &HeaderJWK{
				Crv: jwk.Crv,
				Kty: jwk.Kty,
				X:   jwk.X,
				Y:   jwk.Y,
			}
		}
		log.Println("protected")
		DumpJson(protected)

		body := Req{
			Protected: mustBase64Json(protected),
		}
		if req.Payload != nil {
			body.Payload = mustBase64Json(req.Payload)
		} else {
			body.Payload = ""
		}
		sign, e := client.JWK.sign(body.Protected + "." + body.Payload)
		if e != nil {
			return nil, e
		}
		body.Signature = sign
		log.Println("body")
		DumpJson(body)
		r.SetBody(body)
	}
	if req.Result != nil {
		r.SetResult(req.Result)
	}
	res, e := r.Send()
	httpBody := ""
	log.Println(e)
	if res != nil {
		log.Println(res.Status())
		log.Println(res.Header())
		httpBody = string(res.Body())
		log.Println(httpBody)
	}
	if e != nil || !isSuccess(res.StatusCode()) {
		if e == nil {
			e = errors.New(httpBody)
		}
		return nil, e
	}
	return res, nil
}

func (client *AcmeClient) newNonce() (string, error) {
	e := client.InitDirectory()
	if e != nil {
		return "", e
	}
	res, e := resty.New().R().Head(client.Directory.NewNonce)
	if e != nil || !isSuccess(res.StatusCode()) {
		log.Println(e)
		return "", e
	}
	return res.Header()["Replay-Nonce"][0], nil
}

func (client *AcmeClient) InitDirectory() error {
	if client.Directory != nil {
		return nil
	}
	log.Println("------------------InitDirectory")
	rtn := &AcmeDirectory{}
	// r := resty.New().R()
	// r.SetResult(rtn)
	// res, e := r.Get("https://acme-staging-v02.api.letsencrypt.org/directory")

	// if e != nil || !isSuccess(res.StatusCode()) {
	// 	log.Println(e)
	// 	log.Println(res.StatusCode())
	// 	log.Println(res.Status())
	// 	log.Println(string(res.Body()))
	// 	return e
	// }
	// client.Directory = rtn
	// return nil
	_, e := client.request(HttpRequestParam{
		Url:    "https://acme-staging-v02.api.letsencrypt.org/directory",
		Method: http.MethodGet,
		Result: rtn,
	})
	if e != nil {
		return e
	}
	client.Directory = rtn
	return nil
}

func (client *AcmeClient) InitAccount() error {
	if client.Account != nil {
		return nil
	}
	e := client.InitKey()
	if e != nil {
		return e
	}
	log.Println("------------------InitAccount")

	e = client.InitDirectory()
	if e != nil {
		return e
	}

	rtn := &AcmeAccount{}
	body := HttpRequestParam{
		Url:    client.Directory.NewAccount,
		Method: http.MethodPost,
		Payload: NewAccountPayload{
			TermsOfServiceAgreed: true,
			Contact:              []string{"mailto:i@izzp.me"},
		},
		Result: rtn,
	}
	res, e := client.request(body)
	if e != nil {
		return e
	}
	rtn.Kid = res.Header()["Location"][0]
	client.Account = rtn
	DumpJson(rtn)
	return nil
}

func (client *AcmeClient) NewOrder(identifiers []Identifier) (*Order, error) {
	log.Println("----------------------------newOrder")
	e := client.InitAccount()
	if e != nil {
		return nil, e
	}
	rtn := &Order{}
	req := HttpRequestParam{
		Url:    client.Directory.NewOrder,
		Method: http.MethodPost,
		Kid:    client.Account.Kid,
		Result: rtn,
		Payload: NewOrderPayload{
			Identifiers: identifiers,
		},
	}
	res, e := client.request(req)
	if e != nil {
		return nil, e
	}
	rtn.Url = res.Header()["Location"][0]
	return rtn, nil
}

func (client *AcmeClient) GetOrderInfo(url string) (*OrderInfo, error) {
	log.Println("------------------GetOrderInfo")
	rtn := &OrderInfo{}
	_, e := client.request(HttpRequestParam{
		Url:     url,
		Method:  http.MethodPost,
		Kid:     client.Account.Kid,
		Payload: nil,
		Result:  rtn,
	})
	if e != nil {
		return nil, e
	}
	return rtn, nil
}

func (client *AcmeClient) FetchOrder(orderUrl string) (*Order, error) {
	log.Println("-----------------------FetchOrder")
	e := client.InitAccount()
	if e != nil {
		return nil, e
	}
	rtn := &Order{}
	_, e = client.request(HttpRequestParam{
		Url:    orderUrl,
		Method: http.MethodPost,
		Kid:    client.Account.Kid,
		Result: rtn,
	})
	if e != nil {
		return nil, e
	}
	return rtn, nil
}

func (client *AcmeClient) GetChallenge(url string) (*Challenge, error) {
	log.Println("------------------GetChallenge")
	rtn := &Challenge{}
	r := resty.New().R()
	r.SetResult(rtn)
	res, e := r.Get(url)
	if e != nil || !isSuccess(res.StatusCode()) {
		log.Println(e)
		log.Println(res.Status())
		log.Println(res.Header())
		body := string(res.Body())
		log.Println(body)
		if e == nil {
			e = errors.New(body)
		}
		return nil, e
	}
	return rtn, nil
}

func (client *AcmeClient) SubmitChallenge(challengeUrl string) (*Challenge, error) {
	log.Println("------------------------SubmitChallenge")
	rtn := &Challenge{}
	_, e := client.request(HttpRequestParam{
		Url:     challengeUrl,
		Method:  http.MethodPost,
		Kid:     client.Account.Kid,
		Payload: map[string]any{},
		Result:  rtn,
	})
	if e != nil {
		return nil, e
	}
	return rtn, nil
}

func (client *AcmeClient) GenDNSToken(token string) string {
	pk := client.JWK.Encode()
	b := sha256.Sum256([]byte(pk))
	print := base64.RawURLEncoding.EncodeToString(b[:])
	s := token + "." + print
	b = sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func (client *AcmeClient) FinalizePost(order *Order) (*Order, error) {
	certJwk := NewECDSA()
	pk := certJwk.PrivateKey()
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: order.Identifiers[0].Value},
		DNSNames: utils.SliceMap(order.Identifiers, func(v Identifier) string { return v.Value }),
	}, pk)
	if e != nil {
		return nil, e
	}
	payload := CSRPayload{
		Csr: base64.RawURLEncoding.EncodeToString(csr),
	}
	rtn := &Order{}
	res, e := client.request(HttpRequestParam{
		Url:     order.Finalize,
		Method:  http.MethodPost,
		Kid:     client.Account.Kid,
		Payload: payload,
		Result:  rtn,
	})
	if res != nil {
		value, e := strconv.Atoi(res.Header().Get("Retry-After"))
		if e == nil {
			rtn.RetryAfter = value
		}
		rtn.Url = res.Header().Get("Location")
	}
	return rtn, e
}

func (client *AcmeClient) FinalizeGet(order *Order) (*Order, error) {
	rtn := &Order{}
	res, e := client.request(HttpRequestParam{
		Url:    order.Finalize,
		Method: http.MethodPost,
		Kid:    client.Account.Kid,
		Result: rtn,
	})
	if res != nil {
		header := res.Header()
		values := header["Retry-After"]
		if len(values) > 0 {
			value, e := strconv.Atoi(values[0])
			if e == nil {
				rtn.RetryAfter = value
			}
		}
	}
	return rtn, e

}

func (client *AcmeClient) NewOrderGet() (*Order, error) {
	rtn := &Order{}
	e := client.InitDirectory()
	if e != nil {
		return nil, e
	}
	_, e = client.request(HttpRequestParam{
		Url:    client.Directory.NewOrder,
		Method: http.MethodPost,
		Kid:    client.Account.Kid,
		Result: rtn,
	})
	return rtn, e
}

func (client *AcmeClient) DownloadCert(url string) (*resty.Response, error) {
	res, e := client.request(HttpRequestParam{
		Url:    url,
		Method: http.MethodPost,
		Kid:    client.Account.Kid,
	})
	return res, e
}
