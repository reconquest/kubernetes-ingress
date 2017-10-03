package nginx

import (
	"fmt"
	"strings"

	api_v1 "k8s.io/client-go/pkg/api/v1"
	extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

// IngressEx holds an Ingress along with Secrets and Endpoints of the services
// that are referenced in this Ingress
type IngressEx struct {
	Ingress       *extensions.Ingress
	TLSSecrets    map[string]*api_v1.Secret
	JWTKey        *api_v1.Secret
	Endpoints     map[string][]string
	EndpointsInfo map[string][]EndpointInfo
}

// TODO
type EndpointInfo struct {
	Address string
	Info    map[string]interface{}
}

type Labels map[string]string

func (labels Labels) String() string {
	result := []string{}

	for key, value := range labels {
		result = append(result, fmt.Sprintf("%s:%s", key, value))
	}

	return strings.Join(result, ",")
}
