package main

import (
	"context"
	"time"

	"flag"

	"github.com/andreaskaris/veth-ethtool/pkg/config"
	"github.com/andreaskaris/veth-ethtool/pkg/ethtool"
	"github.com/andreaskaris/veth-ethtool/pkg/pod"
	"github.com/vishvananda/netlink"
	"k8s.io/klog"
)

var (
	configFile     = flag.String("config-file", "/etc/veth-ethtool/config.json", "location of configuration file")
	resyncInterval = flag.Int("resync-interval", 30, "resync interval in seconds")
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
	klog.Info("Running initial sync")
	sync(conf)

	ctx := context.Background()
	ch := make(chan netlink.LinkUpdate)
	netlink.LinkSubscribe(ch, ctx.Done())
	ticker := time.NewTicker(time.Duration(*resyncInterval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case update := <-ch:
			l := update.Link
			linkName := l.Attrs().Name
			klog.V(2).Infof("Detected link event for link %q", linkName)
			if l.Attrs().OperState != netlink.OperDown {
				syncLink(conf, l)
			}
		case <-ticker.C:
			klog.V(2).Info("Timer fired, running periodic sync")
			sync(conf)
		case <-ctx.Done():
			return
		}
	}
}

func sync(conf *config.Config) {
	links, err := netlink.LinkList()
	if err != nil {
		klog.Fatalf("could not list links, err: %q", err)
	}
	for _, l := range links {
		syncLink(conf, l)
	}
}

func syncLink(conf *config.Config, l netlink.Link) {
	linkName := l.Attrs().Name
	klog.V(2).Infof("Running sync for link %q", linkName)

	p, err := pod.GetOwnerOfLink(l)
	if err != nil {
		klog.V(2).Infof("Could not find pod, err: %q", err)
		return
	}
	klog.V(2).Infof("Found pod link %q, pod: %+v", linkName, p)

	klog.V(2).Infof("Applying ethernet-configs: %+v", conf.EthernetConfigs)
	for _, e := range conf.EthernetConfigs {
		if e.Match(p.Metadata.Namespace, p.Metadata.Name) {
			for field, enable := range e.EthtoolSettings {
				if out, err := ethtool.Set(linkName, field, enable); err != nil {
					klog.Warningf("could not apply ethtool settings, out: %q, err: %q", string(out), err)
				}
			}
		}
	}
}
