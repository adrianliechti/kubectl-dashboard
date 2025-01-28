package main

import (
	_ "github.com/adrianliechti/kubectl-dashboard/pkg/config"
	"github.com/adrianliechti/kubectl-dashboard/pkg/server"
)

func main() {
	s, err := server.New()

	if err != nil {
		panic(err)
	}

	if err := s.ListenAndServe(); err != nil {
		panic(err)
	}
}
