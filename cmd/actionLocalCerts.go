package main

import "fmt"

func actionLocalCerts(context *Context) error {
	certs, e := context.Client.GetLocalCerts()
	if e != nil {
		fmt.Println("error", e)
		return nil
	}
	fmt.Println("certs: ", len(certs))
	for _, cert := range certs {
		fmt.Println("-----")
		fmt.Println("path: ", cert.Path)
		fmt.Println("certs:", len(cert.Certs))
		for _, c := range cert.Certs {
			fmt.Println("  --")
			fmt.Println("  Subject: ", c.Subject)
			fmt.Println("  dns: ", c.DNSNames)
			fmt.Println("  validity: ", c.NotBefore, " - ", c.NotAfter)
		}
	}
	return nil
}
