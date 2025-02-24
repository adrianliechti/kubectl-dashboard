package config

import (
	"os"

	"github.com/spf13/pflag"
)

const (
	Version   = "0.3.0"
	UserAgent = "kubectl-dashboard"
)

func init() {
	pflag.String("port", "random", "port to listen to for incoming HTTP requests")
	pflag.String("kubeconfig", "", "path to kubeconfig file")

	pflag.Parse()

	pflag.CommandLine = pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)
}
