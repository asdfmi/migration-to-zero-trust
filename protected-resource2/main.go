package main

import (
	"log"
	"net/http"
)

func main() {
	h := http.NewServeMux()
	h.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	log.Printf("protected-resource2 listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", h))
}
