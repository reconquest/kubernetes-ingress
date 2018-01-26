package nginx

import (
	"fmt"
	"strings"
)

// EndpointInfo describes pod-level information about given endpoint.
type EndpointInfo struct {
	Address   string
	Namespace string
	Pod       string
	Container string
	PodLabels Labels
}

func NewDefaultEndpointInfo() EndpointInfo {
	upstream := NewUpstreamHTTPWithDefaultServer("default")
	return EndpointInfo{
		Address: fmt.Sprintf(
			"%s:%s",
			upstream.UpstreamServers[0].Address,
			upstream.UpstreamServers[0].Port,
		),
	}
}

func (info EndpointInfo) GetMapValues() map[string]string {
	return map[string]string{
		"namespace":  info.Namespace,
		"pod":        info.Pod,
		"container":  info.Container,
		"pod_labels": info.PodLabels.String(),
	}
	//for _, variable := range []string{
	//    "namespace",
	//    "pod",
	//    "container",
	//    "pod_labels",
	//} {

	//}
}

type Labels map[string]string

func (labels Labels) String() string {
	result := []string{}

	for key, value := range labels {
		result = append(result, fmt.Sprintf("%s:%s", key, value))
	}

	return strings.Join(result, ",")
}
