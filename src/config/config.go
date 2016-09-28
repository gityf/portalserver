package config

import (
	"io/ioutil"
	"encoding/json"
)

type PortalServerConfig struct {
	Port          int    `json:"port"`
	PprofPort     int    `json:"profport"`
	SharedSecret  string `json:"secret"`
	AuthType      string `json:"auth_type"`
	RetryTime     int    `json:"retry"`
	Timeout       int    `json:"timeout"`
	BrasPort      int    `json:"bras_port"`
	BrasIP        string `json:"bras_ip"`
	PortalVersion int    `json:"portal_version"`
}

var Cfg PortalServerConfig

func ParseConf(file string) (err error) {
	cnt, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}

	err = json.Unmarshal(cnt, &Cfg);
	return
}