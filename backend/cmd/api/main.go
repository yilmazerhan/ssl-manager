package main

import (
	"log"
	"net/http"

	"github.com/yilmazerhan/ssl-manager/backend/internal/api"
	"github.com/yilmazerhan/ssl-manager/backend/internal/ca"
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/config"
	"github.com/yilmazerhan/ssl-manager/backend/internal/order"
)

func main() {
	cfg := config.Load()

	certs := certificate.NewMemoryStore()
	authorities := ca.Registry(ca.NewLetsEncrypt(), ca.NewZeroSSL())
	orders := order.NewService(certs, authorities)

	router := api.NewRouter(certs, orders)

	log.Printf("ssl-manager api listening on %s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, router); err != nil {
		log.Fatal(err)
	}
}
