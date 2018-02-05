package nginx

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"sync"
	"text/template"

	"github.com/golang/glog"
)

type Server interface {
	// Type returns type of given server. Could be http or stream.
	Type() string
}

type IngressNginxConfig interface {
	// Type returns type of given ingress nginx config. Could be http or stream.
	Type() string
}

const dhparamFilename = "dhparam.pem"

// TLSSecretFileMode defines the default filemode for files with TLS Secrets
const TLSSecretFileMode = 0600
const jwkSecretFileMode = 0644

// NginxController Updates NGINX configuration, starts and reloads NGINX
type NginxController struct {
	nginxConfdPath            string
	nginxSecretsPath          string
	local                     bool
	healthStatus              bool
	nginxConfTemplatePath     string
	nginxMapsConfTemplatePath string
	nginxIngressTempatePath   string

	templates *sync.Map
}

// IngressNginxConfig describes an NGINX configuration for HTTP service
type IngressNginxConfigHTTP struct {
	Namespace   string
	IngressName string
	Upstreams   []UpstreamHTTP
	Servers     []ServerHTTP
	Keepalive   string
	Maps        []Map
}

func (http IngressNginxConfigHTTP) Type() string {
	return "http"
}

// IngressNginxConfig describes an NGINX configuration for stream service
type IngressNginxConfigStream struct {
	Namespace   string
	IngressName string
	Upstream    UpstreamStream
	Server      ServerStream
	Maps        []Map
}

func (stream IngressNginxConfigStream) Type() string {
	return "stream"
}

// Upstream describes an NGINX upstream for HTTP service.
type UpstreamHTTP struct {
	Name            string
	UpstreamServers []UpstreamServer
	StickyCookie    string
	LBMethod        string
}

// Upstream describes an NGINX upstream for stream service.
type UpstreamStream struct {
	Name            string
	UpstreamServers []UpstreamServer
	LBMethod        string
}

// UpstreamServer describes a server in an NGINX upstream
type UpstreamServer struct {
	Address string
	Port    string
}

// Map represents map directive in NGINX config
type Map struct {
	Source   string
	Target   string
	Variable string
	Values   map[string]string
}

type ServerHTTP struct {
	ServerSnippets        []string
	Name                  string
	ServerTokens          string
	Locations             []Location
	SSL                   bool
	SSLCertificate        string
	SSLCertificateKey     string
	StatusZone            string
	HTTP2                 bool
	RedirectToHTTPS       bool
	SSLRedirect           bool
	ProxyProtocol         bool
	HSTS                  bool
	HSTSMaxAge            int64
	HSTSIncludeSubdomains bool
	ProxyHideHeaders      []string
	ProxyPassHeaders      []string

	// http://nginx.org/en/docs/http/ngx_http_realip_module.html
	RealIPHeader    string
	SetRealIPFrom   []string
	RealIPRecursive bool

	JWTKey      string
	JWTRealm    string
	JWTToken    string
	JWTLoginURL string

	Ports    []int
	SSLPorts []int
}

func (http ServerHTTP) Type() string {
	return "http"
}

// Server describes an Stream NGINX server
type ServerStream struct {
	Ports               []int
	ServerSnippets      []string
	ProxyConnectTimeout string
	ProxyBufferSize     string
}

func (stream ServerStream) Type() string {
	return "stream"
}

// Location describes an NGINX location
type Location struct {
	LocationSnippets     []string
	Path                 string
	Upstream             UpstreamHTTP
	ProxyConnectTimeout  string
	ProxyReadTimeout     string
	ClientMaxBodySize    string
	Websocket            bool
	Rewrite              string
	SSL                  bool
	ProxyBuffering       bool
	ProxyBuffers         string
	ProxyBufferSize      string
	ProxyMaxTempFileSize string
}

// NginxMainConfig describe the main NGINX configuration file
type NginxMainConfig struct {
	ServerNamesHashBucketSize string
	ServerNamesHashMaxSize    string
	LogFormat                 string
	HealthStatus              bool
	HTTPSnippets              []string
	// http://nginx.org/en/docs/http/ngx_http_ssl_module.html
	SSLProtocols           string
	SSLPreferServerCiphers bool
	SSLCiphers             string
	SSLDHParam             string
	HTTP2                  bool
	ServerTokens           string
	ProxyProtocol          bool
	WorkerProcesses        string
	WorkerCPUAffinity      string
}

// NewUpstreamHTTPWithDefaultServer creates an upstream with the default server.
// proxy_pass to an upstream with the default server returns 502.
// We use it for services that have no endpoints
func NewUpstreamHTTPWithDefaultServer(name string) UpstreamHTTP {
	return UpstreamHTTP{
		Name:            name,
		UpstreamServers: []UpstreamServer{UpstreamServer{Address: "127.0.0.1", Port: "8181"}},
	}
}

// NewUpstreamStreamWithDefaultServer creates an upstream with the default server.
// proxy_pass to an upstream with the default server returns EOF.
// We use it for services that have no endpoints
func NewUpstreamStreamWithDefaultServer(name string) UpstreamStream {
	return UpstreamStream{
		Name:            name,
		UpstreamServers: []UpstreamServer{UpstreamServer{Address: "127.0.0.1", Port: "8181"}},
	}
}

// NewNginxController creates a NGINX controller
func NewNginxController(
	nginxConfPath string,
	local bool,
	healthStatus bool,
	nginxConfTemplatePath string,
	nginxMapsConfTemplatePath string,
	nginxIngressTemplatePath string,
) (*NginxController, error) {
	ngxc := NginxController{
		nginxConfdPath:            path.Join(nginxConfPath, "conf.d"),
		nginxSecretsPath:          path.Join(nginxConfPath, "secrets"),
		local:                     local,
		healthStatus:              healthStatus,
		nginxConfTemplatePath:     nginxConfTemplatePath,
		nginxMapsConfTemplatePath: nginxMapsConfTemplatePath,
		nginxIngressTempatePath:   nginxIngressTemplatePath,
		templates:                 &sync.Map{},
	}

	cfg := &NginxMainConfig{
		ServerNamesHashMaxSize: NewDefaultConfig().MainServerNamesHashMaxSize,
		ServerTokens:           NewDefaultConfig().ServerTokens,
		WorkerProcesses:        NewDefaultConfig().MainWorkerProcesses,
	}
	ngxc.UpdateMainConfigFile(cfg)
	ngxc.UpdateMapsConfigFile([]Map{})

	return &ngxc, nil
}

// DeleteIngress deletes the configuration file, which corresponds for the
// specified ingress from NGINX conf directory
func (nginx *NginxController) DeleteIngress(name string) {
	if nginx.local {
		return
	}

	var filename string
	for _, module := range []string{"http", "stream"} {
		moduleFilename := nginx.getIngressNginxConfigFileName(module, name)
		if isFileExists(moduleFilename) {
			filename = moduleFilename
			break
		}
	}

	if filename == "" {
		glog.Errorf("Failed to delete ingress %s: no file with config found")
		return
	}

	glog.V(3).Infof("deleting %v", filename)
	if err := os.Remove(filename); err != nil {
		glog.Errorf("Failed to delete %v: %v", filename, err)
	}
}

// AddOrUpdateIngress creates or updates a file with
// the specified configuration for the specified ingress
func (nginx *NginxController) AddOrUpdateIngress(name string, config IngressNginxConfig) {
	glog.V(3).Infof("Updating NGINX configuration")
	filename := nginx.getIngressNginxConfigFileName(config.Type(), name)
	nginx.templateIt(config, filename)
}

// AddOrUpdateDHParam creates the servers dhparam.pem file
func (nginx *NginxController) AddOrUpdateDHParam(dhparam string) (string, error) {
	fileName := nginx.nginxSecretsPath + "/" + dhparamFilename
	if !nginx.local {
		pem, err := os.Create(fileName)
		if err != nil {
			return fileName, fmt.Errorf("Couldn't create file %v: %v", fileName, err)
		}
		defer pem.Close()

		_, err = pem.WriteString(dhparam)
		if err != nil {
			return fileName, fmt.Errorf("Couldn't write to pem file %v: %v", fileName, err)
		}
	}
	return fileName, nil
}

// AddOrUpdateSecretFile creates a file with the specified name, content and mode.
func (nginx *NginxController) AddOrUpdateSecretFile(name string, content []byte, mode os.FileMode) string {
	filename := nginx.getSecretFileName(name)

	if !nginx.local {
		file, err := ioutil.TempFile(nginx.nginxSecretsPath, name)
		if err != nil {
			glog.Fatalf("Couldn't create a temp file for the secret file %v: %v", name, err)
		}

		err = file.Chmod(mode)
		if err != nil {
			glog.Fatalf("Couldn't change the mode of the temp secret file %v: %v", file.Name(), err)
		}

		_, err = file.Write(content)
		if err != nil {
			glog.Fatalf("Couldn't write to the temp secret file %v: %v", file.Name(), err)
		}

		err = file.Close()
		if err != nil {
			glog.Fatalf("Couldn't close the temp secret file %v: %v", file.Name(), err)
		}

		err = os.Rename(file.Name(), filename)
		if err != nil {
			glog.Fatalf("Fail to rename the temp secret file %v to %v: %v", file.Name(), filename, err)
		}
	}

	return filename
}

// DeleteSecretFile the file with a Secret
func (nginx *NginxController) DeleteSecretFile(name string) {
	filename := nginx.getSecretFileName(name)
	glog.V(3).Infof("deleting %v", filename)

	if !nginx.local {
		if err := os.Remove(filename); err != nil {
			glog.Warningf("Failed to delete %v: %v", filename, err)
		}
	}

}

func (nginx *NginxController) getIngressNginxConfigFileName(ingressType, name string) string {
	return path.Join(nginx.nginxConfdPath, ingressType+"-"+name+".conf")
}

func (nginx *NginxController) getSecretFileName(name string) string {
	return path.Join(nginx.nginxSecretsPath, name)
}

func (nginx *NginxController) templateIt(config IngressNginxConfig, filename string) {
	tmpl := nginx.getTemplate(nginx.nginxIngressTempatePath)
	glog.V(3).Infof("Writing NGINX conf to %v", filename)

	if glog.V(3) {
		tmpl.Execute(os.Stdout, config)
	}

	if !nginx.local {
		w, err := os.Create(filename)
		if err != nil {
			glog.Fatalf("Failed to open %v: %v", filename, err)
		}
		defer w.Close()

		if err := tmpl.Execute(w, config); err != nil {
			glog.Fatalf("Failed to write template %v", err)
		}
	} else {
		// print conf to stdout here
	}

	glog.V(3).Infof("NGINX configuration file had been updated")
}

func (nginx *NginxController) getTemplate(path string) *template.Template {
	if tmpl, ok := nginx.templates.Load(path); ok {
		return tmpl.(*template.Template)
	}

	tmpl, err := template.New(path).ParseFiles(path)
	if err != nil {
		glog.Fatalf("Failed to parse template file %s: %v", path, err)
	}

	nginx.templates.Store(path, tmpl)

	return tmpl
}

// Reload reloads NGINX
func (nginx *NginxController) Reload() error {
	if !nginx.local {
		if err := shellOut("nginx -t"); err != nil {
			return fmt.Errorf("Invalid nginx configuration detected, not reloading: %s", err)
		}
		if err := shellOut("nginx -s reload"); err != nil {
			return fmt.Errorf("Reloading NGINX failed: %s", err)
		}
	} else {
		glog.V(3).Info("Reloading nginx")
	}
	return nil
}

// Reload reloads NGINX
func (nginx *NginxController) Reopen() error {
	if !nginx.local {
		if err := shellOut("nginx -s reopen"); err != nil {
			return fmt.Errorf("Reopening NGINX log files failed: %s", err)
		}
	} else {
		glog.V(3).Info("Reopening nginx log files")
	}
	return nil
}

// Start starts NGINX
func (nginx *NginxController) Start(done chan error) {
	if !nginx.local {
		cmd := exec.Command("nginx")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			glog.Fatalf("Failed to start nginx: %v", err)
		}
		go func() {
			done <- cmd.Wait()
		}()
	} else {
		glog.V(3).Info("Starting nginx")
	}
}

// Quit shutdowns NGINX gracefully
func (nginx *NginxController) Quit() {
	if !nginx.local {
		if err := shellOut("nginx -s quit"); err != nil {
			glog.Fatalf("Failed to quit nginx: %v", err)
		}
	} else {
		glog.V(3).Info("Quitting nginx")
	}
}

func createDir(path string) {
	if err := os.Mkdir(path, os.ModeDir); err != nil {
		glog.Fatalf("Couldn't create directory %v: %v", path, err)
	}
}

func shellOut(cmd string) (err error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	glog.V(3).Infof("executing %s", cmd)

	command := exec.Command("sh", "-c", cmd)
	command.Stdout = &stdout
	command.Stderr = &stderr

	err = command.Start()
	if err != nil {
		return fmt.Errorf("Failed to execute %v, err: %v", cmd, err)
	}

	err = command.Wait()
	if err != nil {
		return fmt.Errorf("Command %v stdout: %q\nstderr: %q\nfinished with error: %v", cmd,
			stdout.String(), stderr.String(), err)
	}
	return nil
}

// UpdateMainConfigFile update the main NGINX configuration file
func (nginx *NginxController) UpdateMainConfigFile(cfg *NginxMainConfig) {
	cfg.HealthStatus = nginx.healthStatus

	tmpl := nginx.getTemplate(nginx.nginxConfTemplatePath)

	filename := "/etc/nginx/nginx.conf"
	glog.V(3).Infof("Writing NGINX conf to %v", filename)

	if glog.V(3) {
		tmpl.Execute(os.Stdout, cfg)
	}

	if !nginx.local {
		w, err := os.Create(filename)
		if err != nil {
			glog.Fatalf("Failed to open %v: %v", filename, err)
		}
		defer w.Close()

		if err := tmpl.Execute(w, cfg); err != nil {
			glog.Fatalf("Failed to write template %v", err)
		}
	}

	glog.V(3).Infof("The main NGINX configuration file had been updated")
}

func (nginx *NginxController) UpdateMapsConfigFile(maps []Map) {
	tmpl := nginx.getTemplate(nginx.nginxMapsConfTemplatePath)

	filename := "/etc/nginx/maps.conf"
	glog.V(3).Infof("Writing NGINX conf to %v", filename)

	if glog.V(3) {
		tmpl.Execute(os.Stdout, maps)
	}

	if !nginx.local {
		w, err := os.Create(filename)
		if err != nil {
			glog.Fatalf("Failed to open %v: %v", filename, err)
		}
		defer w.Close()

		if err := tmpl.Execute(w, maps); err != nil {
			glog.Fatalf("Failed to write template %v", err)
		}
	}

	glog.V(3).Infof("The NGINX maps configuration file had been updated")
}

func isFileExists(filename string) bool {
	file, err := os.OpenFile(filename, os.O_RDONLY, 0644)
	defer file.Close()
	return !os.IsNotExist(err)
}
