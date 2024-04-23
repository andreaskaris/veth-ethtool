package pod

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// Metadata holds a pod's metadata.
type Metadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// Pod is a pod object.
type Pod struct {
	ID       string   `json:"id"`
	Metadata Metadata `json:"metadata"`
}

// Items is a list of Pods.
type Items struct {
	Items []Pod `json:"items"`
}

// Get returns the Pod for the provided id.
func Get(id string) (Pod, error) {
	var items Items
	var pod Pod

	out, err := crictlPods(id)
	if err != nil {
		return pod, err
	}
	err = json.Unmarshal([]byte(out), &items)
	if err != nil {
		return pod, err
	}
	if len(items.Items) == 0 {
		return pod, fmt.Errorf("received an empty result")
	}
	if len(items.Items) != 1 {
		return pod, fmt.Errorf("expected to receive a single pod, but got %d instead", len(items.Items))
	}
	return items.Items[0], nil
}

var crictlPods = func(id string) (string, error) {
	cmd := exec.Command("crictl", "pods", "--id", id, "-o", "json")
	out, err := cmd.Output()
	return string(out), err
}
