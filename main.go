package main

import (
	"context"
	"fmt"
	"os"

	"flag"

	"github.com/andreaskaris/veth-ethtool/pkg/config"
	"github.com/andreaskaris/veth-ethtool/pkg/ethtool"
	"github.com/andreaskaris/veth-ethtool/pkg/pod"
	"github.com/vishvananda/netlink"
)

var (
	configFile = flag.String("config-file", "/etc/veth-ethtool/config.json", "location of configuration file")
)

func fatal(msg string) {
	_, _ = fmt.Fprint(os.Stderr, msg)
	os.Exit(1)
}

func main() {
	flag.Parse()

	conf, err := config.New(*configFile)
	if err != nil {
		fatal(fmt.Sprintf("could not parse configuration file %q, err: %q", *configFile, err))
	}

	ctx := context.Background()
	ch := make(chan netlink.LinkUpdate)
	netlink.LinkSubscribe(ch, ctx.Done())
	for {
		select {
		case update := <-ch:
			l := update.Link
			fmt.Println(l)
			if l.Attrs().OperState != netlink.OperDown {
				linkName := l.Attrs().Name
				p, err := pod.Get(linkName)
				if err != nil {
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
