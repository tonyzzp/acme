package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/manifoldco/promptui"
	"github.com/tonyzzp/acme"
	"github.com/tonyzzp/acme/utils"
)

type Context struct {
	Client *acme.Client
}

type MenuItem struct {
	Label  string
	Action func(context *Context) error
}

var ErrExit = errors.New("exit")

func main() {
	file, e := os.OpenFile("log.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
	if e != nil {
		panic(e)
	}
	log.SetFlags(0)
	log.SetOutput(file)

	actions := []MenuItem{
		{
			Label:  "exit",
			Action: func(context *Context) error { return ErrExit },
		},
		{
			Label:  "my private key",
			Action: actionMyPrivateKey,
		},
		{
			Label:  "my account",
			Action: actionMyAccount,
		},
		{
			Label:  "fetch account status online",
			Action: actionFetchAccount,
		},
		{
			Label:  "del local account",
			Action: actionDelAccount,
		},
		{
			Label:  "local orders",
			Action: actionLocalOrders,
		},
		{
			Label:  "clean local orders",
			Action: actionCleanLocalOrders,
		},
		{
			Label:  "new order",
			Action: actionNewOrder,
		},
		{
			Label:  "order auth",
			Action: actionOrderAuth,
		},
		{
			Label:  "local certs",
			Action: actionLocalCerts,
		},
	}

	context := &Context{
		Client: acme.NewAcmeClient("data"),
	}

	var showMenu func()
	showMenu = func() {
		menu := promptui.Select{
			Label: "menu",
			Items: utils.SliceMap(actions, func(v MenuItem) string { return v.Label }),
			Size:  10,
		}
		index, _, e := menu.Run()
		if e != nil {
			os.Exit(1)
		}
		item := actions[index]
		e = item.Action(context)
		if e == nil {
			showMenu()
		} else if e == ErrExit {
			os.Exit(0)
		} else {
			fmt.Println(e)
			os.Exit(1)
		}
	}
	showMenu()
}
