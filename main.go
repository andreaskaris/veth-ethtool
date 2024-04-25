package main

import (
	"context"
	"fmt"

	"flag"

	"github.com/andreaskaris/veth-ethtool/pkg/config"
	"github.com/andreaskaris/veth-ethtool/pkg/ethtool"
	"github.com/andreaskaris/veth-ethtool/pkg/pod"
	"github.com/vishvananda/netlink"
	"k8s.io/klog"
)

var (
	configFile = flag.String("config-file", "/etc/veth-ethtool/config.json", "location of configuration file")
)

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()
	flag.Parse()

	conf, err := config.New(*configFile)
	if err != nil {
		klog.Fatalf("could not parse configuration file %q, err: %q", *configFile, err)
	}

	klog.Info("veth-ethtool daemon started")

	ctx := context.Background()
	ch := make(chan netlink.LinkUpdate)
	netlink.LinkSubscribe(ch, ctx.Done())
	for {
		select {
		case update := <-ch:
			l := update.Link
			linkName := l.Attrs().Name
			klog.V(2).Infof("Detected link event for link %q", linkName)
			if l.Attrs().OperState != netlink.OperDown {
				klog.V(2).Infof("Detected link up event for link %q", linkName)
				p, err := pod.GetOwnerOfLink(l)
				if err != nil {
					klog.V(2).Infof("Could not find pod, err: %q", err)
					continue
				}
				for _, e := range conf.EthernetConfigs {
					if e.Match(p.Metadata.Namespace, p.Metadata.Name) {
						for field, enable := range e.EthtoolSettings {
							if out, err := ethtool.Set(linkName, field, enable); err != nil {
								fmt.Println(out, err)
							}
						}
					}
				}
			}
		case <-ctx.Done():
			return
		}
	}
}
