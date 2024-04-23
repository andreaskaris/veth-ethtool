package pod

import (
	"strings"
	"testing"
)

const (
	noPodOutput = `{
  "items": [
  ]
}
`
	podOutput = `{
  "items": [
    {
      "id": "2fdb5f5befab3847cc5d9af011a8b5a1e03978b28eb01727f8461324b3d78188",
      "metadata": {
        "name": "example",
        "uid": "cef146f2-486d-4813-9892-25221f31eaba",
        "namespace": "nad",
        "attempt": 0
      },
      "state": "SANDBOX_READY",
      "createdAt": "1713882627747415346",
      "labels": {
        "app": "httpd",
        "io.kubernetes.container.name": "POD",
        "io.kubernetes.pod.name": "example",
        "io.kubernetes.pod.namespace": "nad",
        "io.kubernetes.pod.uid": "cef146f2-486d-4813-9892-25221f31eaba"
      },
      "annotations": {
        "k8s.v1.cni.cncf.io/networks": "tuningnad",
        "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{\"k8s.v1.cni.cncf.io/networks\":\"tuningnad\"},\"labels\":{\"app\":\"httpd\"},\"name\":\"example\",\"namespace\":\"nad\"},\"spec\":{\"containers\":[{\"command\":[\"sleep\",\"3600\"],\"image\":\"quay.io/akaris/fedora:sip\",\"name\":\"httpd\",\"ports\":[{\"containerPort\":8080}],\"securityContext\":{\"allowPrivilegeEscalation\":false,\"capabilities\":{\"drop\":[\"ALL\"]}}}],\"securityContext\":{\"runAsNonRoot\":true,\"seccompProfile\":{\"type\":\"RuntimeDefault\"}}}}\n",
        "kubernetes.io/config.seen": "2024-04-23T14:30:27.385006710Z",
        "kubernetes.io/config.source": "api",
        "openshift.io/scc": "restricted-v2",
        "seccomp.security.alpha.kubernetes.io/pod": "runtime/default"
      },
      "runtimeHandler": ""
    }
  ]
}
`
)

var fakeCrictlPods = func(id string) (string, error) {
	if id == "2fdb5f5befab384" {
		return podOutput, nil
	}
	return noPodOutput, nil
}

func TestGet(t *testing.T) {
	crictlPods = fakeCrictlPods
	tcs := []struct {
		pid    string
		errStr string
	}{
		{"2fdb5f5befab384", ""},
		{"", "empty result"},
	}
	for _, tc := range tcs {
		p, err := Get(tc.pid)
		if tc.errStr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.errStr) {
				t.Fatalf("Get(%s): expected to see error %q but got %q", tc.pid, tc.errStr, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("Get(%s): expected to see no error but got %q", tc.pid, err)
		}
		if !strings.Contains(p.ID, tc.pid) {
			t.Fatalf("Get(%s): expected to get pod with PID %q but got %q", tc.pid, tc.pid, p.ID)
		}
	}
}
