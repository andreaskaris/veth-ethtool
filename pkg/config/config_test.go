package config

import (
	"reflect"
	"strings"
	"testing"
)

const (
	configuration = `{
        "ethernet-configs": [
        {"namespace": "default", "name": "red|blue",     "ethtool-settings": {"tx-checksumming": false, "rx-checksumming": false}},
        {"namespace": "test",    "name": "green|yellow", "ethtool-settings": {"tx-checksumming": false, "rx": false}}
        ]
}`
)

var (
	parsedConfiguration Config = Config{
		EthernetConfigs: []EthernetConfig{
			{
				Namespace:       "default",
				Name:            "red|blue",
				EthtoolSettings: map[string]bool{"tx-checksumming": false, "rx-checksumming": false},
			},
			{
				Namespace:       "test",
				Name:            "green|yellow",
				EthtoolSettings: map[string]bool{"tx-checksumming": false, "rx": false},
			},
		},
	}

	fakeReadFile = func(name string) ([]byte, error) {
		return []byte(configuration), nil
	}
)

func TestNew(t *testing.T) {
	readFile = fakeReadFile

	tcs := []struct {
		configuration  string
		errStr         string
		expectedConfig Config
	}{
		{configuration, "", parsedConfiguration},
	}
	for i, tc := range tcs {
		p, err := New("file")
		if tc.errStr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.errStr) {
				t.Fatalf("New(%d): expected to see error %q but got %q", i, tc.errStr, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("New(%d): expected to see no error but got %q", i, err)
		}
		if !reflect.DeepEqual(*p, tc.expectedConfig) {
			t.Fatalf("New(%d): expected to get configuration %+v but got %+v", i, tc.expectedConfig, *p)
		}
	}
}
