package config

import (
	"encoding/json"
	"os"
	"regexp"
)

type EthernetConfig struct {
	Namespace       string          `json:"namespace"`
	Name            string          `json:"name"`
	EthtoolSettings map[string]bool `json:"ethtool-settings"`
}

func (e EthernetConfig) Match(namespace, name string) bool {
	namespaceRegex := regexp.MustCompile(e.Namespace)
	if !namespaceRegex.Match([]byte(namespace)) {
		return false
	}
	nameRegex := regexp.MustCompile(e.Name)
	if !nameRegex.Match([]byte(namespace)) {
		return false
	}
	return true
}

type Config struct {
	EthernetConfigs []EthernetConfig `json:"ethernet-configs"`
}

func New(location string) (*Config, error) {
	content, err := readFile(location)
	if err != nil {
		return nil, err
	}
	c := Config{}
	if err := json.Unmarshal(content, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

var readFile = func(name string) ([]byte, error) {
	return os.ReadFile(name)
}
