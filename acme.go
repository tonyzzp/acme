package acme

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"

	"github.com/go-resty/resty/v2"
	"github.com/tonyzzp/acme/utils"
)

type Client struct {
	JWK         *JWK
	Directory   *Directory
	Account     *Account
	storeRoot   string
	storeCerts  string
	storeOrders string
}

func NewAcmeClient(store string) *Client {
	rtn := &Client{
		storeRoot:   store,
		storeOrders: filepath.Join(store, "orders"),
		storeCerts:  filepath.Join(store, "certs"),
	}
	os.MkdirAll(rtn.storeOrders, os.ModePerm)
	os.MkdirAll(rtn.storeCerts, os.ModePerm)
	return rtn
}

func (client *Client) saveOrder(order *Order) error {
	file := filepath.Join(client.storeOrders, "order-"+utils.Md5String([]byte(order.Uri))+".json")
	return writeJson(file, order)
}

func (client *Client) InitKey() error {
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
		e = writeJson(file, jwk)
		if e != nil {
			return e
		}
	}
	client.JWK = jwk
	return nil
}

func (client *Client) request(req HttpRequestParam) (*resty.Response, error) {
	log.Println("request")
	log.Println("req")
	dumpJson(req)
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
			protected.Jwk = json.RawMessage(client.JWK.Encode())
		}
		log.Println("protected")
		dumpJson(protected)

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
		dumpJson(body)
		r.SetBody(body)
	}
	if req.Result != nil {
		r.SetResult(req.Result)
	}
	res, e := r.Send()
	httpBody := ""
	if e != nil {
		log.Println(e)
	}
	if res != nil {
		log.Println(res.Status())
		log.Println("headers")
		for k, v := range res.Header() {
			log.Println(k, v)
		}
		httpBody = string(res.Body())
		log.Println(httpBody)
	}
	if e != nil || !res.IsSuccess() {
		if e == nil {
			e = errors.New(httpBody)
		}
		return nil, e
	}
	return res, nil
}

func (client *Client) newNonce() (string, error) {
	e := client.InitDirectory()
	if e != nil {
		return "", e
	}
	res, e := resty.New().R().Head(client.Directory.NewNonce)
	if e != nil || !res.IsSuccess() {
		log.Println(e)
		return "", e
	}
	return res.Header()["Replay-Nonce"][0], nil
}

func (client *Client) InitDirectory() error {
	if client.Directory != nil {
		return nil
	}
	log.Println("------------------InitDirectory")
	rtn := &Directory{}
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

func (client *Client) GetLocalAccount() *Account {
	file := filepath.Join(client.storeRoot, "account.json")
	if utils.FileExists(file) {
		bs, e := os.ReadFile(file)
		if e != nil {
			log.Println(e)
			return nil
		}
		account := &Account{}
		e = json.Unmarshal(bs, account)
		if e != nil {
			log.Println(e)
			return nil
		}
		return account
	}
	return nil
}

func (client *Client) DelAccount() error {
	var del = func(file string) error {
		_, e := os.Stat(file)
		if e == nil {
			return os.Remove(file)
		} else {
			err := e.(*os.PathError)
			if err.Err != os.ErrNotExist {
				return e
			}
			return nil
		}
	}
	e := del(filepath.Join(client.storeRoot, "account.json"))
	if e != nil {
		return e
	}
	e = del(filepath.Join(client.storeRoot, "account.jwk.json"))
	if e == nil {
		client.JWK = nil
		client.Account = nil
	}
	return e
}

func (client *Client) InitAccount() error {
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

	file := filepath.Join(client.storeRoot, "account.json")
	if utils.FileExists(file) {
		bs, e := os.ReadFile(file)
		if e != nil {
			log.Println(e)
			return e
		}
		account := &Account{}
		e = json.Unmarshal(bs, account)
		if e != nil {
			log.Println(e)
			return e
		}
		client.Account = account
		return nil
	}

	rtn := &Account{}
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
	rtn.Uri = res.Header()["Location"][0]
	client.Account = rtn
	dumpJson(rtn)
	e = writeJson(file, rtn)
	if e != nil {
		log.Println(e)
		return e
	}
	return nil
}

func (client *Client) FetchAccount() (*Account, error) {
	e := client.InitAccount()
	if e != nil {
		return nil, e
	}
	rtn := &Account{}
	_, e = client.request(HttpRequestParam{
		Url:    client.Account.Uri,
		Method: http.MethodPost,
		Kid:    client.Account.Uri,
		Result: rtn,
	})
	if e != nil {
		return nil, e
	}
	rtn.Uri = client.Account.Uri
	file := filepath.Join(client.storeRoot, "account.json")
	e = writeJson(file, rtn)
	if e != nil {
		return nil, e
	}
	return rtn, nil
}

func (client *Client) GetLocalOrders() ([]*Order, error) {
	entries, e := os.ReadDir(client.storeOrders)
	if e != nil {
		log.Println("read dir error", e)
		return nil, e
	}
	rtn := make([]*Order, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		file := filepath.Join(client.storeOrders, entry.Name())
		bs, e := os.ReadFile(file)
		if e != nil {
			log.Println(e)
			return nil, e
		}
		order := &Order{}
		e = json.Unmarshal(bs, order)
		if e != nil {
			log.Println("read local order file failed")
			log.Println(file)
			log.Println(e)
		} else {
			rtn = append(rtn, order)
		}
	}
	return rtn, nil
}

func (client *Client) DelLocalOrders() error {
	entries, e := os.ReadDir(client.storeOrders)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		file := filepath.Join(client.storeOrders, entry.Name())
		e = os.Remove(file)
		if e != nil {
			return e
		}
	}
	return nil
}

func (client *Client) DelOrder(order *Order) error {
	file := filepath.Join(client.storeOrders, "order-"+utils.Md5String([]byte(order.Uri))+".json")
	e := os.Remove(file)
	return e
}

func (client *Client) NewOrder(identifiers []Identifier) (*Order, error) {
	log.Println("----------------------------newOrder")
	e := client.InitAccount()
	if e != nil {
		return nil, e
	}
	rtn := &Order{}
	req := HttpRequestParam{
		Url:    client.Directory.NewOrder,
		Method: http.MethodPost,
		Kid:    client.Account.Uri,
		Result: rtn,
		Payload: NewOrderPayload{
			Identifiers: identifiers,
		},
	}
	res, e := client.request(req)
	if e != nil {
		return nil, e
	}
	rtn.Uri = res.Header()["Location"][0]
	dumpJson(rtn)
	e = client.saveOrder(rtn)
	if e != nil {
		log.Println("保存order到本地失败", e)
	}
	return rtn, nil
}

func (client *Client) GetOrderAuth(authUrl string) (*Authorization, error) {
	log.Println("------------------GetOrderInfo")
	e := client.InitAccount()
	if e != nil {
		log.Println(e)
		return nil, e
	}
	rtn := &Authorization{}
	_, e = client.request(HttpRequestParam{
		Url:     authUrl,
		Method:  http.MethodPost,
		Kid:     client.Account.Uri,
		Payload: nil,
		Result:  rtn,
	})
	if e != nil {
		return nil, e
	}
	return rtn, nil
}

func (client *Client) FetchOrder(orderUrl string) (*Order, error) {
	log.Println("-----------------------FetchOrder")
	e := client.InitAccount()
	if e != nil {
		return nil, e
	}
	rtn := &Order{}
	_, e = client.request(HttpRequestParam{
		Url:    orderUrl,
		Method: http.MethodPost,
		Kid:    client.Account.Uri,
		Result: rtn,
	})
	if e != nil {
		return nil, e
	}
	rtn.Uri = orderUrl
	client.saveOrder(rtn)
	return rtn, nil
}

func (client *Client) SubmitChallenge(challengeUrl string) (*Challenge, error) {
	log.Println("------------------------SubmitChallenge")
	rtn := &Challenge{}
	_, e := client.request(HttpRequestParam{
		Url:     challengeUrl,
		Method:  http.MethodPost,
		Kid:     client.Account.Uri,
		Payload: map[string]any{},
		Result:  rtn,
	})
	if e != nil {
		return nil, e
	}
	return rtn, nil
}

func (client *Client) GenDNSToken(token string) string {
	pk := client.JWK.Encode()
	b := sha256.Sum256([]byte(pk))
	print := base64.RawURLEncoding.EncodeToString(b[:])
	s := token + "." + print
	b = sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func (client *Client) Finalize(order *Order) (*Order, error) {
	certJwk := NewECDSA()
	dir := filepath.Join(client.storeCerts, order.Identifiers[0].Value)
	os.MkdirAll(dir, os.ModePerm)
	file := filepath.Join(dir, "pk.json")
	e := writeJson(file, certJwk)
	if e != nil {
		log.Println("保证域名私钥失败", e)
		return nil, e
	}
	pk := certJwk.PrivateKey()
	bs, e := convertPkToPEM(pk)
	if e != nil {
		log.Println("转换私钥失败", e)
		return nil, e
	}
	file = filepath.Join(dir, "privkey.pem")
	e = os.WriteFile(file, bs, os.ModePerm)
	if e != nil {
		log.Println("保证域名私钥失败", e)
		return nil, e
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: order.Identifiers[0].Value},
		DNSNames: utils.SliceMap(order.Identifiers, func(v Identifier) string { return v.Value }),
	}, pk)
	if e != nil {
		return nil, e
	}
	payload := FinalizePayload{
		Csr: base64.RawURLEncoding.EncodeToString(csr),
	}
	rtn := &Order{}
	res, e := client.request(HttpRequestParam{
		Url:     order.Finalize,
		Method:  http.MethodPost,
		Kid:     client.Account.Uri,
		Payload: payload,
		Result:  rtn,
	})
	if res != nil && res.IsSuccess() {
		value, e := strconv.Atoi(res.Header().Get("Retry-After"))
		if e == nil {
			rtn.RetryAfter = value
		}
		rtn.Uri = res.Header().Get("Location")
		if rtn.Uri == "" {
			rtn.Uri = order.Uri
		}
		client.saveOrder(rtn)
	}
	return rtn, e
}

func (client *Client) DownloadCert(order *Order) (dir string, cert string, e error) {
	res, e := client.request(HttpRequestParam{
		Url:    order.Certificate,
		Method: http.MethodPost,
		Kid:    client.Account.Uri,
	})
	if e != nil {
		return "", "", e
	}
	body := string(res.Body())
	if !res.IsSuccess() {
		return "", "", errors.New(body)
	}
	dir = filepath.Join(client.storeCerts, order.Identifiers[0].Value)
	os.MkdirAll(dir, os.ModePerm)
	file := filepath.Join(dir, "fullchain.pem")
	e = os.WriteFile(file, []byte(body), os.ModePerm)
	if e != nil {
		return "", "", e
	}
	return dir, body, nil
}

func (client *Client) GetLocalCerts() ([]Cert, error) {
	rootDir := client.storeCerts
	entries, e := os.ReadDir(client.storeCerts)
	if e != nil {
		return nil, e
	}
	rtn := make([]Cert, 0)
	for _, entry := range entries {
		cert := Cert{}

		dir := filepath.Join(rootDir, entry.Name())
		cert.Path = dir

		jwk, e := ReadJWKFromFile(path.Join(dir, "pk.json"))
		if e != nil {
			log.Println("读取 jwk 失败", entry.Name(), e)
			continue
		}
		cert.JWK = jwk

		bs, e := os.ReadFile(filepath.Join(dir, "privkey.pem"))
		if e != nil {
			log.Println("读取 privkey.pem 失败", entry.Name(), e)
			continue
		}
		cert.PrivateKeyPEM = string(bs)

		bs, e = os.ReadFile(filepath.Join(dir, "fullchain.pem"))
		if e != nil {
			log.Println("读取 fullchain.pem 失败", entry.Name(), e)
			continue
		}
		cert.FullChainPEM = string(bs)

		cert.Certs = []*x509.Certificate{}
		for {
			var block *pem.Block
			block, bs = pem.Decode(bs)
			if block == nil {
				break
			}
			c, e := x509.ParseCertificate(block.Bytes)
			if e != nil {
				fmt.Println("parse cert failed", block, e)
				continue
			}
			cert.Certs = append(cert.Certs, c)
		}
		rtn = append(rtn, cert)
	}
	return rtn, nil
}
