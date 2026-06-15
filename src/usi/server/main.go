// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/server/server/main.go
package main

import (
	"log"
	"net/http"

	pubkeydir "github.com/sphinxorg/protocol/src/usi/server/server"
)

func main() {
	// Use consistent path - will create in server/pubkeydir.db
	store, err := pubkeydir.NewLevelDBStore("")
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	srv := pubkeydir.NewServer(store, nil)

	log.Println("Public Key Directory Server starting on :8080")
	log.Println("Database location: server/pubkeydir.db")
	log.Fatal(http.ListenAndServe(":8080", srv.Handler()))
}
