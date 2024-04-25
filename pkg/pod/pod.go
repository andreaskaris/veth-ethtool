package pod

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/andreaskaris/veth-ethtool/pkg/helpers"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog"
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

// PodList is a list of Pods.
type PodList struct {
	Items []Pod `json:"items"`
}

type Namespace struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

type PodInspect struct {
	Info struct {
		RuntimeSpec struct {
			Linux struct {
				Namespaces []Namespace `json:"namespaces"`
			} `json:"linux"`
		} `json:"runtimeSpec"`
	} `json:"info"`
}

// GetNetns returns the netns (only the name, without the full path) of this pod.
func (p PodInspect) GetNetns() string {
	for _, ns := range p.Info.RuntimeSpec.Linux.Namespaces {
		if ns.Type == helpers.TypeNetwork {
			return path.Base(ns.Path)
		}
	}
	return ""
}

// ListNetnsIDs returns the NetNS IDs for each namespace listed inside dir.
func ListNetnsIDs(dir string) (map[string]int, error) {
	return listNetnsIDs(dir)
}

// GetOwnerOfLink returns the Pod for the provided link.
func GetOwnerOfLink(link netlink.Link) (*Pod, error) {
	// Return if this is not a veth.
	if link.Type() != helpers.TypeVeth {
		return nil, fmt.Errorf("provided link is not a veth")
	}

	// List all namespaces with their IDs.
	netnsIDs, err := ListNetnsIDs(helpers.GetNetNSLocation())
	if err != nil {
		return nil, fmt.Errorf("failed to list all netns IDs, netnsIds: %+v, err: %q", netnsIDs, err)
	}

	// Then, find the name of the namespace with the ID that's shown in
	// link.Attrs().NetNsID.
	linkName := link.Attrs().Name
	var linkNetnsName string
	linkNetnsID := link.Attrs().NetNsID
	for name, id := range netnsIDs {
		if id == linkNetnsID {
			linkNetnsName = name
			break
		}
	}
	if linkNetnsName == "" {
		return nil, fmt.Errorf("could not find namespace name for link; link name: %s, link NetnsID: %d, netnsIDs: %+v",
			linkName, linkNetnsID, netnsIDs)
	}
	klog.V(2).Infof("Found netns %q for link %q", linkNetnsName, linkName)

	// TODO: race condition, link is there before pod is listed -_-
	time.Sleep(2 * time.Second)
	pod, err := findPodForNetns(linkNetnsName)
	if err != nil {
		return nil, err
	}
	return pod, nil
}

// findPodForNetns lists all pods with `crictl pods`, then inspects all pods with `crictl inspectp`. It looks for the
// pod with netns within the list of .info.runtimeSpec.linux.namespaces.
func findPodForNetns(netns string) (*Pod, error) {
	var podList PodList
	out, err := crictl("pods", "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("listing pods failed, out: %q, err: %q", out, err)
	}
	if err := json.Unmarshal(out, &podList); err != nil {
		return nil, err
	}
	for _, pod := range podList.Items {
		pod := pod
		out, err := crictl("inspectp", "-o", "json", pod.ID)
		if err != nil {
			return nil, err
		}
		var podInspect PodInspect
		if err := json.Unmarshal(out, &podInspect); err != nil {
			return nil, err
		}
		if podInspect.GetNetns() == netns {
			return &pod, nil
		}
	}
	return nil, fmt.Errorf("could not find a pod for netns %q", netns)
}

var crictl = func(parameters ...string) ([]byte, error) {
	return helpers.RunCommand("crictl", parameters...)
}

// listNetnsIDs holds the implementation for ListNetnsIDs. It can easily be swapped our for a fake implementation.
var listNetnsIDs = func(dir string) (map[string]int, error) {
	nsIDMap := make(map[string]int)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("could not open directory %q err: %q", dir, err)
	}
	var errs []error
	for _, e := range entries {
		p := path.Join(dir, e.Name())
		f, err := os.Open(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("could not open file %q for reading, err: %q", p, err))
			continue
		}
		id, err := netlink.GetNetNsIdByFd(int(f.Fd()))
		if err != nil {
			errs = append(errs, fmt.Errorf("issue running netlink.GetNetNsIdByFd, file: %q, err: %q", p, err))
			continue
		}
		baseName := path.Base(f.Name())
		nsIDMap[baseName] = id
	}

	return nsIDMap, errors.NewAggregate(errs)
}
