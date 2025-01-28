package server

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/adrianliechti/loop/pkg/kubernetes"
	"github.com/adrianliechti/loop/pkg/system"
	"github.com/spf13/pflag"

	"github.com/pkg/browser"
	"golang.org/x/net/xsrftoken"

	"k8s.io/utils/ptr"

	"k8s.io/dashboard/client"
	"k8s.io/dashboard/csrf"
	"k8s.io/dashboard/types"

	"k8s.io/dashboard/api/pkg/args"
	"k8s.io/dashboard/api/pkg/handler"
	"k8s.io/dashboard/api/pkg/integration"
)

var (
	//go:embed public
	public embed.FS

	name    = "loop-dashboard"
	version = "0.0.1"
)

type Server struct {
	handler http.Handler
}

func New() (*Server, error) {
	// https: //github.com/kubernetes/dashboard/blob/38e970c366d8c32165ff6c4faa3e774efceeb762/modules/api/pkg/args/args.go#L74
	if args.KubeconfigPath() == "" {
		pflag.Set("kubeconfig", kubernetes.ConfigPath())
	}

	if host, port, err := net.SplitHostPort(args.Address()); err == nil {
		println("set insecure", host, port)
		pflag.Set("insecure-bind-address", host)
		pflag.Set("insecure-port", port)
	}

	client.Init(
		client.WithUserAgent(name),
		client.WithKubeconfig(args.KubeconfigPath()),
		client.WithMasterUrl(args.ApiServerHost()),
		client.WithInsecureTLSSkipVerify(args.ApiServerSkipTLSVerify()),
	)

	k, err := kubernetes.New()

	if err != nil {
		return nil, err
	}

	if _, err := client.InClusterClient().Discovery().ServerVersion(); err != nil {
		panic(err)
	}

	mux := http.NewServeMux()

	api, err := handler.CreateHTTPAPIHandler(integration.NewIntegrationManager())

	if err != nil {
		panic(err)
	}

	// https://github.com/kubernetes/dashboard/blob/38e970c366d8c32165ff6c4faa3e774efceeb762/modules/web/pkg/config/handler.go#L27
	mux.HandleFunc("GET /config", handleConfig)

	// https://github.com/kubernetes/dashboard/blob/38e970c366d8c32165ff6c4faa3e774efceeb762/modules/web/pkg/systembanner/handler.go#L25
	mux.HandleFunc("GET /systembanner", handleSystemBanner)

	// https://github.com/kubernetes/dashboard/blob/38e970c366d8c32165ff6c4faa3e774efceeb762/modules/web/pkg/settings/handler.go#L54
	mux.HandleFunc("GET /settings/cani", handleSettingsCanI)
	mux.HandleFunc("GET /settings", handleSettings)
	mux.HandleFunc("PUT /settings", handleSaveSettings)

	mux.HandleFunc("GET /settings/pinnedresources/cani", handleSettingsPinnedResourcesCanI)
	mux.HandleFunc("GET /settings/pinnedresources", handleSettingsPinnedResources)
	mux.HandleFunc("PUT /settings/pinnedresources", handleSettingsSavePinnedResources)
	//mux.HandleFunc("DELETE /settings/pinnedresources/:kind/:nameOrNamespace/:name", handleSettingsDeletePinned)
	//mux.HandleFunc("DELETE /settings/pinnedresources/:kind/:nameOrNamespace", handleSettingsD

	// https://github.com/kubernetes/dashboard/blob/38e970c366d8c32165ff6c4faa3e774efceeb762/modules/auth/pkg/routes/me/handler.go#L26
	mux.HandleFunc("GET /api/v1/me", handleMe)

	// https://github.com/kubernetes/dashboard/blob/38e970c366d8c32165ff6c4faa3e774efceeb762/modules/auth/pkg/routes/login/handler.go#L27
	mux.HandleFunc("POST /api/v1/login", handleLogin)

	// https://github.com/kubernetes/dashboard/blob/38e970c366d8c32165ff6c4faa3e774efceeb762/modules/auth/pkg/routes/csrftoken/handler.go#L27
	mux.HandleFunc("GET /api/v1/csrftoken/{action}", handleCSRF)

	// https://github.com/kubernetes/dashboard/blob/38e970c366d8c32165ff6c4faa3e774efceeb762/modules/api/pkg/handler/apihandler.go#L106
	mux.Handle("/api/v1/", api)

	// https://github.com/kubernetes/dashboard/blob/38e970c366d8c32165ff6c4faa3e774efceeb762/modules/api/main.go#L82
	mux.Handle("/api/sockjs/", handler.CreateAttachHandler("/api/sockjs"))

	fs, _ := fs.Sub(public, "public")
	mux.Handle("/", http.FileServerFS(fs))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := client.GetBearerToken(r)

		if token != "" {
			if creds, err := k.Credentials(); err == nil {
				token = creds.Token
			}
		}

		if token != "" {
			client.SetAuthorizationHeader(r, token)
		}

		mux.ServeHTTP(w, r)
	})

	return &Server{
		handler: handler,
	}, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *Server) ListenAndServe() error {
	var port int

	if _, val, err := net.SplitHostPort(args.Address()); err == nil {
		port, _ = strconv.Atoi(val)
	}

	if port == 0 {
		val, err := system.FreePort(9090)

		if err != nil {
			return err
		}

		port = val
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := fmt.Sprintf("http://localhost:%d", port)

	go func() {
		time.Sleep(250 * time.Millisecond)

		if ctx.Err() != nil {
			return
		}

		println("Dashboard available on " + addr)

		browser.OpenURL(addr)
	}()

	return http.ListenAndServe(args.InsecureAddress(), s)
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	type Response struct {
		ServerTime int64  `json:"serverTime"`
		UserAgent  string `json:"userAgent"`
		Version    string `json:"version"`
	}

	result := &Response{
		ServerTime: time.Now().UTC().UnixNano() / 1e6,
		UserAgent:  name,
		Version:    version,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func handleSystemBanner(w http.ResponseWriter, r *http.Request) {
	type SystemBannerSeverity string

	type Response struct {
		Message  string               `json:"message"`
		Severity SystemBannerSeverity `json:"severity"`
	}

	const (
		SystemBannerSeverityInfo    SystemBannerSeverity = "INFO"
		SystemBannerSeverityWarning SystemBannerSeverity = "WARNING"
		SystemBannerSeverityError   SystemBannerSeverity = "ERROR"
	)

	result := &Response{
		Message:  "",
		Severity: SystemBannerSeverityInfo,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	c, err := client.Client(r)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if _, err = c.Discovery().ServerVersion(); err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	result := &types.User{
		Name:          "User",
		Authenticated: true,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	type Request struct {
		Token string `json:"token"`
	}

	var req Request
	json.NewDecoder(r.Body).Decode(&req)

	if req.Token == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	client.SetAuthorizationHeader(r, req.Token)

	c, err := client.Client(r)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err = c.Discovery().ServerVersion(); err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	type Response struct {
		Token string `json:"token"`
	}

	result := &Response{
		Token: req.Token,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func handleCSRF(w http.ResponseWriter, r *http.Request) {
	key := csrf.Key()
	action := r.PathValue("action")

	type Response struct {
		Token string `json:"token"`
	}

	token := xsrftoken.Generate(key, "none", action)

	result := &Response{
		Token: token,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func handleSettingsCanI(w http.ResponseWriter, r *http.Request) {
	type Response struct {
		Allowed bool `json:"allowed"`
	}

	result := &Response{
		Allowed: false,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	type Response struct {
		ClusterName                      *string  `json:"clusterName,omitempty"`
		ItemsPerPage                     *int     `json:"itemsPerPage,omitempty"`
		LabelsLimit                      *int     `json:"labelsLimit,omitempty"`
		LogsAutoRefreshTimeInterval      *int     `json:"logsAutoRefreshTimeInterval,omitempty"`
		ResourceAutoRefreshTimeInterval  *int     `json:"resourceAutoRefreshTimeInterval,omitempty"`
		DisableAccessDeniedNotifications *bool    `json:"disableAccessDeniedNotifications,omitempty"`
		HideAllNamespaces                *bool    `json:"hideAllNamespaces,omitempty"`
		DefaultNamespace                 *string  `json:"defaultNamespace,omitempty"`
		NamespaceFallbackList            []string `json:"namespaceFallbackList,omitempty"`
	}

	result := &Response{
		ClusterName:                      ptr.To(""),
		ItemsPerPage:                     ptr.To(10),
		LabelsLimit:                      ptr.To(3),
		LogsAutoRefreshTimeInterval:      ptr.To(5),
		ResourceAutoRefreshTimeInterval:  ptr.To(10),
		DisableAccessDeniedNotifications: ptr.To(false),
		HideAllNamespaces:                ptr.To(false),
		DefaultNamespace:                 ptr.To("default"),
		NamespaceFallbackList:            []string{"default"},
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusBadRequest)
}

func handleSettingsPinnedResourcesCanI(w http.ResponseWriter, r *http.Request) {
	type Response struct {
		Allowed bool `json:"allowed"`
	}

	result := &Response{
		Allowed: false,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func handleSettingsPinnedResources(w http.ResponseWriter, r *http.Request) {
	type Response struct {
		Kind        string `json:"kind"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
		Namespaced  bool   `json:"namespaced"`
		Namespace   string `json:"namespace,omitempty"`
	}

	result := []Response{}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func handleSettingsSavePinnedResources(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusBadRequest)
}
