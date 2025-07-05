package public

import (
	"CloudWaf/core"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"time"
)

var (
	SyslogPath = core.AbsPath("./config/syslog.json")
)

type Syslog struct {
	Open bool   `json:"open"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

func SetSysLog(open bool, host string, port int) error {
	syslog := Syslog{
		Open: open,
		Host: host,
		Port: port,
	}
	data, err := json.Marshal(syslog)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(SyslogPath, data, 0644)
	if err != nil {
		return err
	}
	return nil

}

func ReadSyslogConfig() (*Syslog, error) {
	var syslog Syslog
	syslog.Open = false
	syslog.Port = 0
	syslog.Host = ""
	if !FileExists(SyslogPath) {
		return &syslog, errors.New("syslog config file does not exist")
	}
	data, err := ioutil.ReadFile(SyslogPath)
	if err != nil {
		return &syslog, err
	}

	err = json.Unmarshal(data, &syslog)
	if err != nil {
		return &syslog, err
	}
	return &syslog, nil
}

func GetLogsAfterTime(timeThreshold int) ([]map[string]interface{}, error) {
	query := M("totla_log").Where("time >?", []any{timeThreshold}).Limit([]int64{200})
	i, err := query.Select()
	if err != nil {
		return nil, err
	}
	return i, nil
}

func SendLogsToSyslogServer(logs []map[string]interface{}, host string, port int) error {
	addr := net.JoinHostPort(host, IntToString(port))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, log := range logs {
		if path, ok := log["http_log_path"].(string); ok && len(path) > 5 {
			file, err := ReadFile(path)
			if err == nil {
				log["http_log_path"] = file
			}
		}
		logData, err := json.Marshal(log)
		if err != nil {
			continue
		}
		_, err = conn.Write(logData)
		if err != nil {
			continue
		}
	}
	return nil
}

func AddSyslog() {
	if !FileExists(SyslogPath) {
		return
	}
	syslogConfig, err := ReadSyslogConfig()
	if err != nil {
		return
	}
	if syslogConfig.Open {
		currentTime := int(time.Now().Unix() - 120)
		logs, err := GetLogsAfterTime(currentTime)
		if err != nil {
			return
		}
		SendLogsToSyslogServer(logs, syslogConfig.Host, syslogConfig.Port)
	}
}
