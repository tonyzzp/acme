package main

import (
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"time"

	"github.com/tonyzzp/acme"
	"github.com/tonyzzp/acme/utils"
)

func checkError(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	file, e := os.OpenFile("log.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
	if e != nil {
		panic(e)
	}
	log.SetFlags(0)
	log.SetOutput(io.MultiWriter(file, os.Stdout))
	client := acme.NewAcmeClient("")

	order, e := client.NewOrder([]acme.Identifier{
		{
			Type:  "dns",
			Value: "test.izzp.me",
		},
	})
	checkError(e)
	acme.DumpJson(order)

	info, e := client.GetOrderInfo(order.Authorizations[0])
	checkError(e)
	acme.DumpJson(info)

	challenge := utils.SliceFind(info.Challenges, func(v acme.Challenge) bool { return v.Type == "dns-01" })
	acme.DumpJson(challenge)

	challengePass := challenge.Status == "valid"
	if challenge.Status == "pending" {
		dnsToken := client.GenDNSToken(challenge.Token)
		for {
			log.Println("dnsToken", dnsToken)
			log.Println("press y to finalize")
			ok := ""
			fmt.Scanf("%s\n", &ok)
			if ok != "y" {
				os.Exit(0)
			}

			infoRes, _ := client.GetOrderInfo(order.Authorizations[0])
			if infoRes != nil {
				acme.DumpJson(infoRes)
				if infoRes.Status == "valid" {
					log.Println("dns验证通过")
					challengePass = true
					break
				} else if infoRes.Status == "invalid" || infoRes.Status == "expired" {
					log.Println("order状态不对")
					challengePass = true
					break
				}
			}

			challengeRes, _ := client.SubmitChallenge(challenge.Url)
			if challengeRes != nil {
				acme.DumpJson(challengeRes)
			}

			if challengeRes != nil && challengeRes.Status == "valid" {
				challengePass = true
				break
			}
		}
	}

	if !challengePass {
		log.Println("challenge失败")
		os.Exit(-1)
	}

	order, e = client.FinalizePost(order)
	checkError(e)
	if order.Status == "processing" {
		delay := math.Max(float64(order.RetryAfter), 3)
		for {
			time.Sleep(time.Second * time.Duration(delay))
			order, e = client.FetchOrder(order.Url)
			if e != nil {
				os.Exit(-1)
			}
			if order.Status == "valid" && order.Certificate != "" {
				break
			}
		}
	}

	log.Println("start download cert")
	_, e = client.DownloadCert(order.Certificate)
	checkError(e)
}
