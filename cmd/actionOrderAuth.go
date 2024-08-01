package main

import (
	"fmt"
	"math"
	"os"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/tonyzzp/acme"
	"github.com/tonyzzp/acme/utils"
)

func actionOrderAuth(context *Context) error {
	orders, e := context.Client.GetLocalOrders()
	if e != nil {
		fmt.Println("加载本地order失败")
		fmt.Println(e)
		return nil
	}
	if len(orders) == 0 {
		fmt.Println("没有订单")
		return nil
	}
	items := utils.SliceMap(orders, func(order *acme.Order) string { return order.ShortDesc() })
	items = append([]string{"cancel"}, items...)
	p := promptui.Select{
		Label: "选择order",
		Size:  10,
		Items: items,
	}
	index, _, e := p.Run()
	if e != nil {
		fmt.Println(e)
		return nil
	}
	if index == 0 {
		return nil
	}
	order := orders[index-1]
	fmt.Println("你选择的order")
	fmt.Println("uri: ", order.Uri)
	fmt.Println("status: ", order.Status)
	fmt.Println("expires: ", order.Expires)
	fmt.Println("identifiers:")
	utils.DumpJson(order.Identifiers, os.Stdout)

	var showRetryMenu func()
	var actions func()

	actions = func() {
		fmt.Println("获取order状态...")
		orderRes, e := context.Client.FetchOrder(order.Uri)
		if e != nil {
			fmt.Println("获取失败")
			fmt.Println(e)
			showRetryMenu()
			return
		}
		order = orderRes
		fmt.Println("order status: ", order.Status)
		if order.Status == acme.OrderStatusPending {
			fmt.Println("获取授权验证信息...")
			auth, e := context.Client.GetOrderAuth(order.Authorizations[0])
			if e != nil {
				fmt.Println("获取失败")
				fmt.Println(e)
				showRetryMenu()
				return
			}
			challenge := utils.SliceFind(auth.Challenges, func(v acme.Challenge) bool { return v.Type == "dns-01" })
			fmt.Println("你需要完成的授权信息: ")
			fmt.Println("domain: ", "_acme-challenge."+auth.Identifier.Value)
			fmt.Println("TXT: ", context.Client.GenDNSToken(challenge.Token))
			p = promptui.Select{
				Label: "继续操作",
				Items: []string{
					"cancel",
					"continue",
				},
			}
			index, _, e = p.Run()
			if e != nil {
				fmt.Println(e)
				return
			}
			if index == 0 {
				return
			}
			fmt.Println("提交验证...")
			challengeRes, e := context.Client.SubmitChallenge(challenge.Url)
			if e != nil {
				fmt.Println("提交出错")
				fmt.Println(e)
				showRetryMenu()
				return
			}
			challenge = challengeRes
			fmt.Println("challenge status: ", challenge.Status)
			if challenge.Status == "processing" {
				delay := math.Max(float64(order.RetryAfter), 3)
				fmt.Printf("提交成功，等待 %d 秒后验证结果\n", int(delay))
				time.Sleep(time.Second * time.Duration(delay))
				actions()
				return
			} else if challenge.Status == "valid" {
				fmt.Println("challenge状态正常，又验证")
				actions()
				return
			} else {
				fmt.Println("challenge状态不对")
				utils.DumpJson(challenge, os.Stdout)
				showRetryMenu()
				return
			}
		} else if order.Status == acme.OrderStatusProcessing {
			delay := math.Max(float64(order.RetryAfter), 3)
			fmt.Printf("等待 %d 秒后验证结果\n", int(delay))
			time.Sleep(time.Second * time.Duration(delay))
			actions()
			return
		} else if order.Status == acme.OrderStatusInvalid {
			fmt.Println("订单无效")
			fmt.Println("获取详情...")
			auth, e := context.Client.GetOrderAuth(order.Authorizations[0])
			if e != nil {
				fmt.Println(e)
				showRetryMenu()
				return
			}
			utils.DumpJson(auth, os.Stdout)
			showRetryMenu()
			return
		} else if order.Status == acme.OrderStatusReady {
			fmt.Println("提交证书请求...")
			_, e := context.Client.Finalize(order)
			if e != nil {
				fmt.Println(e)
				showRetryMenu()
				return
			}
			fmt.Println("提交成功")
			actions()
			return
		} else if order.Status == acme.OrderStatusValid || order.Status == acme.OrderStatusReady {
			fmt.Println("下载证书...")
			fmt.Println("url", order.Certificate)
			dir, certs, e := context.Client.DownloadCert(order)
			if e != nil {
				fmt.Println("失败")
				fmt.Println(e)
				showRetryMenu()
				return
			}
			fmt.Println(certs)
			fmt.Println("证书已保存到", dir)
		}
	}

	showRetryMenu = func() {
		p := promptui.Select{
			Label: "选择操作",
			Items: []string{
				"cancel",
				"retry",
			},
		}
		index, _, e = p.Run()
		if index == 0 {
			return
		}
		actions()
	}

	actions()
	return nil
}
