package nginx

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"github.com/nginxinc/kubernetes-ingress/nginx-controller/nginx/plus"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	api_v1 "k8s.io/client-go/pkg/api/v1"
	extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

const emptyHost = ""

// DefaultServerSecretName is the filename of the Secret with a TLS cert and a key for the default server
const DefaultServerSecretName = "default"

// JWTKey is the key of the data field of a Secret where the JWK must be stored.
const JWTKey = "jwk"

// JWTKeyAnnotation is the annotation where the Secret with a JWK is specified.
const JWTKeyAnnotation = "nginx.com/jwt-key"

// Configurator transforms an Ingress resource into NGINX Configuration
type Configurator struct {
	nginx     *NginxController
	config    *Config
	nginxAPI  *plus.NginxAPIController
	ingresses map[string]*IngressEx
}

// NewConfigurator creates a new Configurator
func NewConfigurator(nginx *NginxController, config *Config, nginxAPI *plus.NginxAPIController) *Configurator {
	cnf := Configurator{
		nginx:     nginx,
		config:    config,
		nginxAPI:  nginxAPI,
		ingresses: map[string]*IngressEx{},
	}

	return &cnf
}

// AddOrUpdateDHParam creates a dhparam file with the content of the string.
func (cnf *Configurator) AddOrUpdateDHParam(content string) (string, error) {
	return cnf.nginx.AddOrUpdateDHParam(content)
}

// AddOrUpdateIngress adds or updates NGINX configuration for the Ingress resource
func (cnf *Configurator) AddOrUpdateIngress(ingEx *IngressEx) error {
	cnf.addOrUpdateIngress(ingEx)
	cnf.updateMaps()

	if err := cnf.nginx.Reload(); err != nil {
		return fmt.Errorf("Error when adding or updating ingress %v/%v: %v", ingEx.Ingress.Namespace, ingEx.Ingress.Name, err)
	}
	return nil
}

func (cnf *Configurator) addOrUpdateIngress(ingEx *IngressEx) {
	pems, jwtKeyFileName := cnf.updateSecrets(ingEx)
	nginxCfg := cnf.generateNginxCfg(ingEx, pems, jwtKeyFileName)
	if nginxCfg != nil {
		name := objectMetaToFileName(&ingEx.Ingress.ObjectMeta)
		cnf.nginx.AddOrUpdateIngress(name, nginxCfg)

		cnf.ingresses[getFullIngressName(ingEx.Ingress)] = ingEx
	}
}

func (cnf *Configurator) updateMaps() {
	maps := []Map{}

	for variable, _ := range (EndpointInfo{}).GetMapValues() {
		values := map[string]string{}

		for _, ingress := range cnf.ingresses {
			stream, exists, err := GetMapKeyAsBool(
				ingress.Ingress.Annotations,
				"nginx.org/stream",
				ingress.Ingress,
			)
			if exists {
				if err != nil {
					glog.Error(err)
					continue
				}
			}

			if !stream {
				values[getFullIngressName(ingress.Ingress)] = getMappedVariableName(
					ingress.Ingress.Namespace,
					ingress.Ingress.Name,
					"k8s_upstream_"+variable,
				)
			}
		}

		maps = append(
			maps,
			Map{
				Source:   "$k8s_namespace/$k8s_ingress",
				Variable: fmt.Sprintf("$k8s_upstream_%s", variable),
				Values:   values,
			},
		)
	}

	cnf.nginx.UpdateMapsConfigFile(maps)
}

func (cnf *Configurator) updateSecrets(ingEx *IngressEx) (map[string]string, string) {
	pems := make(map[string]string)

	for _, tls := range ingEx.Ingress.Spec.TLS {
		secretName := tls.SecretName

		pemFileName := cnf.addOrUpdateSecret(ingEx.TLSSecrets[secretName])

		for _, host := range tls.Hosts {
			pems[host] = pemFileName
		}
		if len(tls.Hosts) == 0 {
			pems[emptyHost] = pemFileName
		}
	}

	jwtKeyFileName := ""

	if cnf.isPlus() && ingEx.JWTKey != nil {
		jwtKeyFileName = cnf.addOrUpdateSecret(ingEx.JWTKey)
	}

	return pems, jwtKeyFileName
}

func (cnf *Configurator) generateNginxCfg(ingEx *IngressEx, pems map[string]string, jwtKeyFileName string) IngressNginxConfig {
	ingCfg := cnf.createConfig(ingEx)

	if ingCfg.Enabled {
		if ingCfg.Stream {
			return cnf.generateNginxCfgStream(ingEx, ingCfg)
		} else {
			return cnf.generateNginxCfgHTTP(ingEx, ingCfg, pems, jwtKeyFileName)
		}
	}

	return nil
}

func (cnf *Configurator) generateNginxCfgHTTP(ingEx *IngressEx, ingCfg Config, pems map[string]string, jwtKeyFileName string) IngressNginxConfigHTTP {
	var (
		upstreams   = make(map[string]UpstreamHTTP)
		wsServices  = getWebsocketServices(ingEx)
		spServices  = getSessionPersistenceServices(ingEx)
		rewrites    = getRewrites(ingEx)
		sslServices = getSSLServices(ingEx)
	)

	// default backend
	if ingEx.Ingress.Spec.Backend != nil {
		name := getNameForUpstream(ingEx.Ingress, emptyHost, ingEx.Ingress.Spec.Backend.ServiceName)
		upstream := cnf.createUpstreamHTTP(
			ingEx,
			name,
			ingEx.Ingress.Spec.Backend,
			ingEx.Ingress.Namespace,
			spServices[ingEx.Ingress.Spec.Backend.ServiceName],
			ingCfg.LBMethod,
		)
		upstreams[name] = upstream
	}

	var servers []ServerHTTP

	for _, rule := range ingEx.Ingress.Spec.Rules {
		if rule.IngressRuleValue.HTTP == nil {
			continue
		}
		serverName := rule.Host

		statuzZone := rule.Host

		server := ServerHTTP{
			Name:                  serverName,
			ServerTokens:          ingCfg.ServerTokens,
			HTTP2:                 ingCfg.HTTP2,
			RedirectToHTTPS:       ingCfg.RedirectToHTTPS,
			SSLRedirect:           ingCfg.SSLRedirect,
			ProxyProtocol:         ingCfg.ProxyProtocol,
			HSTS:                  ingCfg.HSTS,
			HSTSMaxAge:            ingCfg.HSTSMaxAge,
			HSTSIncludeSubdomains: ingCfg.HSTSIncludeSubdomains,
			StatusZone:            statuzZone,
			RealIPHeader:          ingCfg.RealIPHeader,
			SetRealIPFrom:         ingCfg.SetRealIPFrom,
			RealIPRecursive:       ingCfg.RealIPRecursive,
			ProxyHideHeaders:      ingCfg.ProxyHideHeaders,
			ProxyPassHeaders:      ingCfg.ProxyPassHeaders,
			ServerSnippets:        ingCfg.ServerSnippets,
			Ports:                 ingCfg.Ports,
			SSLPorts:              ingCfg.SSLPorts,
			Address:               ingCfg.Address,
		}

		if pemFile, ok := pems[serverName]; ok {
			server.SSL = true
			server.SSLCertificate = pemFile
			server.SSLCertificateKey = pemFile
		}

		if jwtKeyFileName != "" {
			server.JWTKey = jwtKeyFileName
			server.JWTRealm = ingCfg.JWTRealm
			server.JWTToken = ingCfg.JWTToken
			server.JWTLoginURL = ingCfg.JWTLoginURL
		}

		var locations []Location
		rootLocation := false

		for _, path := range rule.HTTP.Paths {
			upstreamName := getNameForUpstream(ingEx.Ingress, rule.Host, path.Backend.ServiceName)

			if _, exists := upstreams[upstreamName]; !exists {
				upstream := cnf.createUpstreamHTTP(ingEx, upstreamName, &path.Backend, ingEx.Ingress.Namespace, spServices[path.Backend.ServiceName], ingCfg.LBMethod)
				upstreams[upstreamName] = upstream
			}

			loc := createLocation(pathOrDefault(path.Path), upstreams[upstreamName], &ingCfg, wsServices[path.Backend.ServiceName], rewrites[path.Backend.ServiceName], sslServices[path.Backend.ServiceName])
			locations = append(locations, loc)

			if loc.Path == "/" {
				rootLocation = true
			}
		}

		if rootLocation == false && ingEx.Ingress.Spec.Backend != nil {
			upstreamName := getNameForUpstream(ingEx.Ingress, emptyHost, ingEx.Ingress.Spec.Backend.ServiceName)
			loc := createLocation(pathOrDefault("/"), upstreams[upstreamName], &ingCfg, wsServices[ingEx.Ingress.Spec.Backend.ServiceName], rewrites[ingEx.Ingress.Spec.Backend.ServiceName], sslServices[ingEx.Ingress.Spec.Backend.ServiceName])
			locations = append(locations, loc)
		}

		server.Locations = locations

		servers = append(servers, server)
	}

	var keepalive string
	if ingCfg.Keepalive > 0 {
		keepalive = strconv.FormatInt(ingCfg.Keepalive, 10)
	}

	config := IngressNginxConfigHTTP{
		Namespace:   ingEx.Ingress.Namespace,
		IngressName: ingEx.Ingress.Name,
		Upstreams:   upstreamMapToSlice(upstreams),
		Servers:     servers,
		Keepalive:   keepalive,
		Maps:        getVariableMaps(ingEx),
	}

	return config
}

func (cnf *Configurator) generateNginxCfgStream(ingEx *IngressEx, ingCfg Config) IngressNginxConfigStream {
	var config IngressNginxConfigStream
	if len(ingEx.Ingress.Spec.Rules) > 0 {
		glog.Warning(
			"Stream server type specified, rules directive is not " +
				"supported, ignoring.",
		)
	}

	if ingEx.Ingress.Spec.Backend == nil {
		glog.Error("Stream server type specified, but spec.backend is not defined")
	} else {
		config.Upstream = cnf.createUpstreamStream(
			ingEx,
			getNameForUpstream(ingEx.Ingress, emptyHost, ingEx.Ingress.Spec.Backend.ServiceName),
			ingEx.Ingress.Spec.Backend,
			ingEx.Ingress.Namespace,
			ingCfg.LBMethod,
		)

		config.Server = ServerStream{
			Ports:               ingCfg.Ports,
			ServerSnippets:      ingCfg.ServerSnippets,
			ProxyBufferSize:     ingCfg.ProxyBufferSize,
			ProxyConnectTimeout: ingCfg.ProxyConnectTimeout,
			ProxyTimeout:        ingCfg.ProxyTimeout,
			Address:             ingCfg.Address,
		}
	}

	config.Namespace = ingEx.Ingress.Namespace
	config.IngressName = ingEx.Ingress.Name
	config.Maps = getVariableMaps(ingEx)

	return config
}

func getVariableMaps(ingEx *IngressEx) []Map {
	maps := map[string]Map{}

	for key, _ := range ingEx.Endpoints {
		bucket := ingEx.EndpointsInfo[key]

		// If there's no matching endpoints for ingress, we should
		// provide dummy maps to satisfy maps.conf mappings.
		if len(bucket) == 0 {
			bucket = []EndpointInfo{
				NewDefaultEndpointInfo(),
			}
		}

		for _, info := range bucket {
			for variable, value := range info.GetMapValues() {
				if _, ok := maps[variable]; !ok {
					maps[variable] = Map{
						Source: "$upstream_addr",
						Variable: getMappedVariableName(
							ingEx.Ingress.Namespace,
							ingEx.Ingress.Name,
							"k8s_upstream_"+variable,
						),
						Values: map[string]string{},
					}
				}

				address := `~` + regexp.QuoteMeta(info.Address) + `$`

				maps[variable].Values[address] = fmt.Sprintf(
					"%q",
					value,
				)
			}
		}
	}

	result := []Map{}
	for _, variableMap := range maps {
		result = append(result, variableMap)
	}

	return result
}

func (cnf *Configurator) createConfig(ingEx *IngressEx) Config {
	ingCfg := *cnf.config

	//Override from annotation
	if lbMethod, exists := ingEx.Ingress.Annotations["nginx.org/lb-method"]; exists {
		ingCfg.LBMethod = lbMethod
	}

	stream, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "nginx.org/stream", ingEx.Ingress)
	if exists {
		if err != nil {
			glog.Error(err)
		} else {
			ingCfg.Stream = stream
		}
	}

	if serverSnippets, exists, err := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "nginx.org/server-snippets", ingEx.Ingress, "\n"); exists {
		if err != nil {
			glog.Error(err)
		} else {
			ingCfg.ServerSnippets = serverSnippets
		}
	}

	if proxyConnectTimeout, exists := ingEx.Ingress.Annotations["nginx.org/proxy-connect-timeout"]; exists {
		ingCfg.ProxyConnectTimeout = proxyConnectTimeout
	}

	if proxyBufferSize, exists := ingEx.Ingress.Annotations["nginx.org/proxy-buffer-size"]; exists {
		ingCfg.ProxyBufferSize = proxyBufferSize
	}

	ports, sslPorts := getServicesPorts(ingEx)
	if len(ports) > 0 {
		ingCfg.Ports = ports
	}

	ingCfg.Enabled = true
	if listenAddress, exists := ingEx.Ingress.Annotations["nginx.org/listen-address"]; exists {
		ingCfg.Enabled = false

		addrs, err := net.InterfaceAddrs()
		if err != nil {
			glog.Errorf("unable to list interface addresses: %s", err)
		} else {
			listenIP := net.ParseIP(listenAddress)
			for _, addr := range addrs {
				hostIP, _, _ := net.ParseCIDR(addr.String())

				if hostIP.String() == listenIP.String() {
					ingCfg.Address = listenIP.String()
					ingCfg.Enabled = true
				}
			}
		}
	}

	if !stream {
		if len(sslPorts) > 0 {
			ingCfg.SSLPorts = sslPorts
		}

		if serverTokens, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "nginx.org/server-tokens", ingEx.Ingress); exists {
			if err != nil {
				if cnf.isPlus() {
					ingCfg.ServerTokens = ingEx.Ingress.Annotations["nginx.org/server-tokens"]
				} else {
					glog.Error(err)
				}
			} else {
				ingCfg.ServerTokens = "off"
				if serverTokens {
					ingCfg.ServerTokens = "on"
				}
			}
		}

		if locationSnippets, exists, err := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "nginx.org/location-snippets", ingEx.Ingress, "\n"); exists {
			if err != nil {
				glog.Error(err)
			} else {
				ingCfg.LocationSnippets = locationSnippets
			}
		}

		if proxyReadTimeout, exists := ingEx.Ingress.Annotations["nginx.org/proxy-read-timeout"]; exists {
			ingCfg.ProxyReadTimeout = proxyReadTimeout
		}
		if proxyHideHeaders, exists, err := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "nginx.org/proxy-hide-headers", ingEx.Ingress, ","); exists {
			if err != nil {
				glog.Error(err)
			} else {
				ingCfg.ProxyHideHeaders = proxyHideHeaders
			}
		}
		if proxyPassHeaders, exists, err := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "nginx.org/proxy-pass-headers", ingEx.Ingress, ","); exists {
			if err != nil {
				glog.Error(err)
			} else {
				ingCfg.ProxyPassHeaders = proxyPassHeaders
			}
		}
		if clientMaxBodySize, exists := ingEx.Ingress.Annotations["nginx.org/client-max-body-size"]; exists {
			ingCfg.ClientMaxBodySize = clientMaxBodySize
		}
		if redirectToHTTPS, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "nginx.org/redirect-to-https", ingEx.Ingress); exists {
			if err != nil {
				glog.Error(err)
			} else {
				ingCfg.RedirectToHTTPS = redirectToHTTPS
			}
		}
		if sslRedirect, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "ingress.kubernetes.io/ssl-redirect", ingEx.Ingress); exists {
			if err != nil {
				glog.Error(err)
			} else {
				ingCfg.SSLRedirect = sslRedirect
			}
		}
		if proxyBuffering, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "nginx.org/proxy-buffering", ingEx.Ingress); exists {
			if err != nil {
				glog.Error(err)
			} else {
				ingCfg.ProxyBuffering = proxyBuffering
			}
		}

		if hsts, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "nginx.org/hsts", ingEx.Ingress); exists {
			if err != nil {
				glog.Error(err)
			} else {
				parsingErrors := false

				hstsMaxAge, existsMA, err := GetMapKeyAsInt(ingEx.Ingress.Annotations, "nginx.org/hsts-max-age", ingEx.Ingress)
				if existsMA && err != nil {
					glog.Error(err)
					parsingErrors = true
				}
				hstsIncludeSubdomains, existsIS, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "nginx.org/hsts-include-subdomains", ingEx.Ingress)
				if existsIS && err != nil {
					glog.Error(err)
					parsingErrors = true
				}

				if parsingErrors {
					glog.Errorf("Ingress %s/%s: There are configuration issues with hsts annotations, skipping annotions for all hsts settings", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName())
				} else {
					ingCfg.HSTS = hsts
					if existsMA {
						ingCfg.HSTSMaxAge = hstsMaxAge
					}
					if existsIS {
						ingCfg.HSTSIncludeSubdomains = hstsIncludeSubdomains
					}
				}
			}
		}

		if proxyBuffers, exists := ingEx.Ingress.Annotations["nginx.org/proxy-buffers"]; exists {
			ingCfg.ProxyBuffers = proxyBuffers
		}
		if proxyMaxTempFileSize, exists := ingEx.Ingress.Annotations["nginx.org/proxy-max-temp-file-size"]; exists {
			ingCfg.ProxyMaxTempFileSize = proxyMaxTempFileSize
		}

		if cnf.isPlus() {
			if jwtRealm, exists := ingEx.Ingress.Annotations["nginx.com/jwt-realm"]; exists {
				ingCfg.JWTRealm = jwtRealm
			}
			if jwtKey, exists := ingEx.Ingress.Annotations[JWTKeyAnnotation]; exists {
				ingCfg.JWTKey = fmt.Sprintf("%v/%v", ingEx.Ingress.Namespace, jwtKey)
			}
			if jwtToken, exists := ingEx.Ingress.Annotations["nginx.com/jwt-token"]; exists {
				ingCfg.JWTToken = jwtToken
			}
			if jwtLoginURL, exists := ingEx.Ingress.Annotations["nginx.com/jwt-login-url"]; exists {
				ingCfg.JWTLoginURL = jwtLoginURL
			}
		}

		if keepalive, exists, err := GetMapKeyAsInt(ingEx.Ingress.Annotations, "nginx.org/keepalive", ingEx.Ingress); exists {
			if err != nil {
				glog.Error(err)
			} else {
				ingCfg.Keepalive = keepalive
			}
		}
	}

	return ingCfg
}

func getWebsocketServices(ingEx *IngressEx) map[string]bool {
	wsServices := make(map[string]bool)

	if services, exists := ingEx.Ingress.Annotations["nginx.org/websocket-services"]; exists {
		for _, svc := range strings.Split(services, ",") {
			wsServices[svc] = true
		}
	}

	return wsServices
}

func getRewrites(ingEx *IngressEx) map[string]string {
	rewrites := make(map[string]string)

	if services, exists := ingEx.Ingress.Annotations["nginx.org/rewrites"]; exists {
		for _, svc := range strings.Split(services, ";") {
			if serviceName, rewrite, err := parseRewrites(svc); err != nil {
				glog.Errorf("In %v nginx.org/rewrites contains invalid declaration: %v, ignoring", ingEx.Ingress.Name, err)
			} else {
				rewrites[serviceName] = rewrite
			}
		}
	}

	return rewrites
}

func parseRewrites(service string) (serviceName string, rewrite string, err error) {
	parts := strings.SplitN(service, " ", 2)

	if len(parts) != 2 {
		return "", "", fmt.Errorf("Invalid rewrite format: %s", service)
	}

	svcNameParts := strings.Split(parts[0], "=")
	if len(svcNameParts) != 2 {
		return "", "", fmt.Errorf("Invalid rewrite format: %s", svcNameParts)
	}

	rwPathParts := strings.Split(parts[1], "=")
	if len(rwPathParts) != 2 {
		return "", "", fmt.Errorf("Invalid rewrite format: %s", rwPathParts)
	}

	return svcNameParts[1], rwPathParts[1], nil
}

func getSSLServices(ingEx *IngressEx) map[string]bool {
	sslServices := make(map[string]bool)

	if services, exists := ingEx.Ingress.Annotations["nginx.org/ssl-services"]; exists {
		for _, svc := range strings.Split(services, ",") {
			sslServices[svc] = true
		}
	}

	return sslServices
}

func getSessionPersistenceServices(ingEx *IngressEx) map[string]string {
	spServices := make(map[string]string)

	if services, exists := ingEx.Ingress.Annotations["nginx.com/sticky-cookie-services"]; exists {
		for _, svc := range strings.Split(services, ";") {
			if serviceName, sticky, err := parseStickyService(svc); err != nil {
				glog.Errorf("In %v nginx.com/sticky-cookie-services contains invalid declaration: %v, ignoring", ingEx.Ingress.Name, err)
			} else {
				spServices[serviceName] = sticky
			}
		}
	}

	return spServices
}

func parseStickyService(service string) (serviceName string, stickyCookie string, err error) {
	parts := strings.SplitN(service, " ", 2)

	if len(parts) != 2 {
		return "", "", fmt.Errorf("Invalid sticky-cookie service format: %s", service)
	}

	svcNameParts := strings.Split(parts[0], "=")
	if len(svcNameParts) != 2 {
		return "", "", fmt.Errorf("Invalid sticky-cookie service format: %s", svcNameParts)
	}

	return svcNameParts[1], parts[1], nil
}

func getServicesPorts(ingEx *IngressEx) ([]int, []int) {
	ports := map[string][]int{}

	annotations := []string{
		"nginx.org/listen-ports",
		"nginx.org/listen-ports-ssl",
	}

	for _, annotation := range annotations {
		if values, exists := ingEx.Ingress.Annotations[annotation]; exists {
			for _, value := range strings.Split(values, ",") {
				if port, err := parsePort(value); err != nil {
					glog.Errorf(
						"In %v %s contains invalid declaration: %v, ignoring",
						ingEx.Ingress.Name,
						annotation,
						err,
					)
				} else {
					ports[annotation] = append(ports[annotation], port)
				}
			}
		}
	}

	return ports[annotations[0]], ports[annotations[1]]
}

func parsePort(value string) (int, error) {
	port, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf(
			"Unable to parse port as integer: %s\n",
			err,
		)
	}

	if port <= 0 {
		return 0, fmt.Errorf(
			"Port number should be greater than zero: %q",
			port,
		)
	}

	return int(port), nil
}

func createLocation(path string, upstream UpstreamHTTP, cfg *Config, websocket bool, rewrite string, ssl bool) Location {
	loc := Location{
		Path:                 path,
		Upstream:             upstream,
		ProxyTimeout:         cfg.ProxyTimeout,
		ProxyConnectTimeout:  cfg.ProxyConnectTimeout,
		ProxyReadTimeout:     cfg.ProxyReadTimeout,
		ClientMaxBodySize:    cfg.ClientMaxBodySize,
		Websocket:            websocket,
		Rewrite:              rewrite,
		SSL:                  ssl,
		ProxyBuffering:       cfg.ProxyBuffering,
		ProxyBuffers:         cfg.ProxyBuffers,
		ProxyBufferSize:      cfg.ProxyBufferSize,
		ProxyMaxTempFileSize: cfg.ProxyMaxTempFileSize,
		LocationSnippets:     cfg.LocationSnippets,
	}

	return loc
}

func (cnf *Configurator) createUpstreamStream(
	ingEx *IngressEx,
	name string,
	backend *extensions.IngressBackend,
	namespace string,
	lbMethod string,
) UpstreamStream {
	var ups UpstreamStream

	if cnf.isPlus() {
		ups = UpstreamStream{Name: name}
	} else {
		ups = NewUpstreamStreamWithDefaultServer(name)
	}

	endps, exists := ingEx.Endpoints[backend.ServiceName+backend.ServicePort.String()]
	if exists {
		var upsServers []UpstreamServer
		for _, endp := range endps {
			addressport := strings.Split(endp, ":")
			upsServers = append(upsServers, UpstreamServer{addressport[0], addressport[1]})
		}
		if len(upsServers) > 0 {
			ups.UpstreamServers = upsServers
		}
	}
	ups.LBMethod = lbMethod
	return ups
}

func (cnf *Configurator) createUpstreamHTTP(
	ingEx *IngressEx,
	name string,
	backend *extensions.IngressBackend,
	namespace string,
	stickyCookie string,
	lbMethod string,
) UpstreamHTTP {
	var ups UpstreamHTTP

	if cnf.isPlus() {
		ups = UpstreamHTTP{Name: name, StickyCookie: stickyCookie}
	} else {
		ups = NewUpstreamHTTPWithDefaultServer(name)
	}

	endps, exists := ingEx.Endpoints[backend.ServiceName+backend.ServicePort.String()]
	if exists {
		var upsServers []UpstreamServer
		for _, endp := range endps {
			addressport := strings.Split(endp, ":")
			upsServers = append(upsServers, UpstreamServer{addressport[0], addressport[1]})
		}
		if len(upsServers) > 0 {
			ups.UpstreamServers = upsServers
		}
	}
	ups.LBMethod = lbMethod
	return ups
}

func pathOrDefault(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func getNameForUpstream(ing *extensions.Ingress, host string, service string) string {
	return fmt.Sprintf("%v-%v-%v-%v", ing.Namespace, ing.Name, host, service)
}

func upstreamMapToSlice(upstreams map[string]UpstreamHTTP) []UpstreamHTTP {
	result := make([]UpstreamHTTP, 0, len(upstreams))

	for _, ups := range upstreams {
		result = append(result, ups)
	}

	return result
}

func getMappedVariableName(namespace string, ingress string, name string) string {
	escape := func(value string) string {
		return regexp.MustCompile(`\W`).ReplaceAllString(value, `_`)
	}

	return fmt.Sprintf(
		"$%s_%s_%s",
		name,
		escape(namespace),
		escape(ingress),
	)
}

// AddOrUpdateSecret creates or updates a file with the content of the secret
func (cnf *Configurator) AddOrUpdateSecret(secret *api_v1.Secret) error {
	cnf.addOrUpdateSecret(secret)

	kind, _ := GetSecretKind(secret)
	if cnf.isPlus() && kind == JWK {
		return nil
	}

	if err := cnf.nginx.Reload(); err != nil {
		return fmt.Errorf("Error when reloading NGINX when updating Secret: %v", err)
	}
	return nil
}

func (cnf *Configurator) addOrUpdateSecret(secret *api_v1.Secret) string {
	name := objectMetaToFileName(&secret.ObjectMeta)

	var data []byte
	var mode os.FileMode

	kind, _ := GetSecretKind(secret)
	if cnf.isPlus() && kind == JWK {
		mode = jwkSecretFileMode
		data = []byte(secret.Data[JWTKey])
	} else {
		mode = TLSSecretFileMode
		data = GenerateCertAndKeyFileContent(secret)
	}
	return cnf.nginx.AddOrUpdateSecretFile(name, data, mode)
}

// AddOrUpdateDefaultServerTLSSecret creates or updates a file with a TLS cert and a key from the secret for the default server.
func (cnf *Configurator) AddOrUpdateDefaultServerTLSSecret(secret *api_v1.Secret) error {
	data := GenerateCertAndKeyFileContent(secret)
	cnf.nginx.AddOrUpdateSecretFile(DefaultServerSecretName, data, TLSSecretFileMode)

	if err := cnf.nginx.Reload(); err != nil {
		return fmt.Errorf("Error when reloading NGINX when updating the default server Secret: %v", err)
	}
	return nil
}

// GenerateCertAndKeyFileContent generates a pem file content from the secret
func GenerateCertAndKeyFileContent(secret *api_v1.Secret) []byte {
	var res bytes.Buffer

	res.Write(secret.Data[api_v1.TLSCertKey])
	res.WriteString("\n")
	res.Write(secret.Data[api_v1.TLSPrivateKeyKey])

	return res.Bytes()
}

// DeleteSecret deletes the file associated with the secret and the configuration files for the Ingress resources. NGINX is reloaded only when len(ings) > 0
func (cnf *Configurator) DeleteSecret(key string, ings []extensions.Ingress) error {
	for _, ing := range ings {
		cnf.nginx.DeleteIngress(objectMetaToFileName(&ing.ObjectMeta))

		delete(cnf.ingresses, getFullIngressName(&ing))
	}

	cnf.nginx.DeleteSecretFile(keyToFileName(key))

	if len(ings) > 0 {
		cnf.updateMaps()

		if err := cnf.nginx.Reload(); err != nil {
			return fmt.Errorf("Error when reloading NGINX when deleting Secret %v: %v", key, err)
		}
	}

	return nil
}

// DeleteIngress deletes NGINX configuration for the Ingress resource
func (cnf *Configurator) DeleteIngress(key string) error {
	delete(cnf.ingresses, key)

	cnf.nginx.DeleteIngress(keyToFileName(key))

	cnf.updateMaps()

	if err := cnf.nginx.Reload(); err != nil {
		return fmt.Errorf("Error when removing ingress %v: %v", key, err)
	}
	return nil
}

// UpdateEndpoints updates endpoints in NGINX configuration for the Ingress resource
func (cnf *Configurator) UpdateEndpoints(ingEx *IngressEx) error {
	cnf.addOrUpdateIngress(ingEx)

	if cnf.isPlus() {
		cnf.updatePlusEndpoints(ingEx)
	} else {
		if err := cnf.nginx.Reload(); err != nil {
			return fmt.Errorf("Error reloading NGINX when updating endpoints for %v/%v: %v", ingEx.Ingress.Namespace, ingEx.Ingress.Name, err)
		}
	}
	return nil
}

func (cnf *Configurator) updatePlusEndpoints(ingEx *IngressEx) {
	if ingEx.Ingress.Spec.Backend != nil {
		name := getNameForUpstream(ingEx.Ingress, emptyHost, ingEx.Ingress.Spec.Backend.ServiceName)
		endps, exists := ingEx.Endpoints[ingEx.Ingress.Spec.Backend.ServiceName+ingEx.Ingress.Spec.Backend.ServicePort.String()]
		if exists {
			err := cnf.nginxAPI.UpdateServers(name, endps)
			if err != nil {
				glog.Warningf("Couldn't update the endponts for %v: %v", name, err)
			}
		}
	}
	for _, rule := range ingEx.Ingress.Spec.Rules {
		if rule.IngressRuleValue.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			name := getNameForUpstream(ingEx.Ingress, rule.Host, path.Backend.ServiceName)
			endps, exists := ingEx.Endpoints[path.Backend.ServiceName+path.Backend.ServicePort.String()]
			if exists {
				err := cnf.nginxAPI.UpdateServers(name, endps)
				if err != nil {
					glog.Warningf("Couldn't update the endponts for %v: %v", name, err)
				}
			}
		}
	}
}

// UpdateConfig updates NGINX Configuration parameters
func (cnf *Configurator) UpdateConfig(config *Config, ingExes []*IngressEx) error {
	cnf.config = config
	mainCfg := &NginxMainConfig{
		HTTPSnippets:              config.MainHTTPSnippets,
		ServerNamesHashBucketSize: config.MainServerNamesHashBucketSize,
		ServerNamesHashMaxSize:    config.MainServerNamesHashMaxSize,
		LogFormat:                 config.MainLogFormat,
		SSLProtocols:              config.MainServerSSLProtocols,
		SSLCiphers:                config.MainServerSSLCiphers,
		SSLDHParam:                config.MainServerSSLDHParam,
		SSLPreferServerCiphers:    config.MainServerSSLPreferServerCiphers,
		HTTP2:             config.HTTP2,
		ServerTokens:      config.ServerTokens,
		ProxyProtocol:     config.ProxyProtocol,
		WorkerProcesses:   config.MainWorkerProcesses,
		WorkerConnections: config.MainWorkerConnections,
		WorkerCPUAffinity: config.MainWorkerCPUAffinity,
	}

	cnf.nginx.UpdateMainConfigFile(mainCfg)

	for _, ingEx := range ingExes {
		cnf.addOrUpdateIngress(ingEx)
	}

	if err := cnf.nginx.Reload(); err != nil {
		return fmt.Errorf("Error when updating config from ConfigMap: %v", err)
	}

	return nil
}

func (cnf *Configurator) isPlus() bool {
	return cnf.nginxAPI != nil
}

func keyToFileName(key string) string {
	return strings.Replace(key, "/", "-", -1)
}

func objectMetaToFileName(meta *meta_v1.ObjectMeta) string {
	return meta.Namespace + "-" + meta.Name
}

func getFullIngressName(ingress *extensions.Ingress) string {
	return fmt.Sprintf(
		"%s/%s",
		ingress.Namespace,
		ingress.Name,
	)
}
