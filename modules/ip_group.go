package modules

import (
	"CloudWaf/core"
	"CloudWaf/public"
	"CloudWaf/types"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func init() {
	core.RegisterModule(&Inset{
		ipData:    "/www/cloud_waf/nginx/conf.d/waf/rule/ip_group.json",
		manm_path: "/www/cloud_waf/nginx/conf.d/waf/rule/cc.json",
		ipWhite:   "/www/cloud_waf/nginx/conf.d/waf/rule/ip_white.json",
		ipBlack:   "/www/cloud_waf/nginx/conf.d/waf/rule/ip_black.json",
	})
}

type Inset struct {
	ipData    string
	manm_path string
	ipWhite   string
	ipBlack   string
}

func (ip *Inset) SetIpGroup(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["data"]; !ok {
		return core.Fail(core.Lan("modules.ip_group.data.missing"))
	}
	if _, ok := params["name"]; !ok {
		return core.Fail(core.Lan("modules.ip_group.name.missing"))
	}
	uid := public.GetUid(request)
	name := params["name"].(string)
	fileData, err := ip.rFile(ip.ipData)
	if err != nil {
		return core.Fail(core.Lan("modules.ip_group.read_file.fail"))
	}
	_, ok := fileData[name]
	if ok {
		return core.Fail(core.Lan("modules.ip_group.name.exists"))
	}
	fileData, err = ip.helpData(params["data"].([]interface{}), fileData, name)
	if err != nil {
		return core.Fail(err)
	}
	for _, fileTime := range fileData {
		sort.Slice(fileTime, func(i, j int) bool {
			return fileTime[0].Time > fileTime[0].Time
		})
	}
	text, status := json.Marshal(fileData)
	if status != nil {
		public.WriteFile(ip.ipData, "{}")
		return core.Fail(status)
	}
	_, err = public.WriteFile(ip.ipData, string(text))
	if err != nil {
		return core.Fail(err)
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	public.WriteOptLog(fmt.Sprintf(core.Lan("modules.ip_group.add.success"), name), public.OPT_LOG_TYPE_SITE_IPGROUP, uid)
	return core.Success(fmt.Sprintf(core.Lan("modules.ip_group.add.success"), name))
}

func (ip *Inset) EditIpGroup(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["name"]; !ok {
		return core.Fail(core.Lan("modules.ip_group.name.missing"))
	}
	if _, ok := params["data"]; !ok {
		return core.Fail(core.Lan("modules.ip_group.data.missing"))
	}
	uid := public.GetUid(request)
	name := params["name"].(string)
	fileData, err := ip.rFile(ip.ipData)
	if err != nil {
		return core.Fail(core.Lan("modules.ip_group.read_file.fail"))
	}
	_, ok := fileData[name]
	if ok {
		delete(fileData, name)
	}
	fileData, err = ip.helpData(params["data"].([]interface{}), fileData, name)
	if err != nil {
		return core.Fail(err)
	}
	for _, fileTime := range fileData {
		sort.Slice(fileTime, func(i, j int) bool {
			return fileTime[0].Time > fileTime[0].Time
		})
	}
	text, status := json.Marshal(fileData)
	if status != nil {
		public.WriteFile(ip.ipData, "{}")
		return core.Fail(status)
	}
	_, err = public.WriteFile(ip.ipData, string(text))
	if err != nil {
		return core.Fail(err)
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	public.WriteOptLog(fmt.Sprintf(core.Lan("modules.ip_group.edit.success"), name), public.OPT_LOG_TYPE_SITE_IPGROUP, uid)
	return core.Success(fmt.Sprintf(core.Lan("modules.ip_group.edit.success"), name))
}

func (ip *Inset) DelIpGroup(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["name"]; !ok {
		return core.Fail(core.Lan("modules.ip_group.name.missing"))
	}
	uid := public.GetUid(request)
	name := params["name"].(string)
	fileData, err := ip.rFile(ip.ipData)
	if err != nil {
		return core.Fail(core.Lan("modules.ip_group.read_file.fail"))
	}
	ipWhite, _ := ip.readIpData(ip.ipWhite)
	for _, values := range ipWhite {
		switch values[0].(type) {
		case string:
			if values[0].(string) == name && values[6].(string) == "ip_group" {
				return core.Fail(core.Lan("modules.ip_group.used_in_whitelist"))
			}
		default:
		}
	}
	ipBlack, _ := ip.readIpData(ip.ipBlack)
	for _, values := range ipBlack {
		switch values[0].(type) {
		case string:
			if values[0].(string) == name && values[6].(string) == "ip_group" {
				return core.Fail(core.Lan("modules.ip_group.used_in_blacklist"))
			}
		default:
		}
	}
	is_mem := ip.readMenData(name)
	if is_mem {
		return core.Fail(core.Lan("modules.ip_group.used_in_man_machine"))
	}
	_, ok := fileData[name]
	if ok {
		delete(fileData, name)
	}
	for _, fileTime := range fileData {
		sort.Slice(fileTime, func(i, j int) bool {
			return fileTime[0].Time > fileTime[0].Time
		})
	}
	text, status := json.Marshal(fileData)
	if status != nil {
		public.WriteFile(ip.ipData, "{}")
		return core.Fail(status)
	}
	_, err = public.WriteFile(ip.ipData, string(text))
	if err != nil {
		return core.Fail(err)
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	public.WriteOptLog(fmt.Sprintf(core.Lan("modules.ip_group.delete.success"), name), public.OPT_LOG_TYPE_SITE_IPGROUP, uid)
	return core.Success(fmt.Sprintf(core.Lan("modules.ip_group.delete.success"), name))
}

func (ip *Inset) GetByNameIp(request *http.Request) core.Response {
	params := struct {
		Name string `json:"name"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.Name == "" {
		return core.Fail(core.Lan("modules.ip_group.name.empty"))
	}
	fileData, err := ip.rFile(ip.ipData)
	if err != nil {
		return core.Fail(core.Lan("modules.ip_group.read_file.fail"))
	}
	ips, ok := fileData[params.Name]
	if !ok {
		return core.Fail(core.Lan("modules.ip_group.not_found"))
	}
	ips_ := make([]string, 0)
	for _, v := range ips {
		ips_ = append(ips_, v.IP)
	}
	return core.Success(ips_)

}

func (ip *Inset) rFile(path string) (map[string][]types.Group, error) {
	jsonData, err := public.ReadFile(path)
	if err != nil {
		jsonData = string([]byte("{}"))
	}
	fileData := make(map[string][]types.Group, 0)
	err = json.Unmarshal([]byte(jsonData), &fileData)
	if err != nil {
		return nil, err
	}
	return fileData, nil
}

func (ip *Inset) helpData(params []interface{}, fileData map[string][]types.Group, name string) (map[string][]types.Group, error) {
	ipSet := make(map[string]interface{})
	for _, v := range params {
		_, ok := ipSet[public.InterfaceToString(v)]
		if ok {
			continue
		}
		v = strings.TrimSpace(public.InterfaceToString(v))
		if len(public.InterfaceToString(v)) > 0 {
			parts := strings.Split(public.InterfaceToString(v), "/")
			if len(parts) > 1 && public.IsIpv6(parts[0]) {
				l, ok := strconv.Atoi(parts[1])
				if ok != nil {
					return nil, ok
				}
				if l < 5 || l > 128 {
					return nil, errors.New(core.Lan("modules.ip_group.ip_format.invalid"))
				}
			}
			if !public.IsIpAddr(public.InterfaceToString(v)) && !public.IsIpNetwork(public.InterfaceToString(v)) && !public.IsIpv6(parts[0]) {
				return nil, errors.New(core.Lan("modules.ip_group.ip_format.incorrect"))
			}
			if public.IsIpv6(public.InterfaceToString(v)) {
				fileData[name] = append(fileData[name], types.Group{
					IP:      public.InterfaceToString(v),
					Network: false,
					Type:    "v6",
					Time:    time.Now().Unix(),
				})
			}
			if len(parts) > 1 && public.IsIpv6(parts[0]) {
				fileData[name] = append(fileData[name], types.Group{
					IP:      public.InterfaceToString(v),
					Network: true,
					Type:    "v6",
					Time:    time.Now().Unix(),
				})
			}
			if public.IsIpv4(public.InterfaceToString(v)) {
				fileData[name] = append(fileData[name], types.Group{
					IP:      public.InterfaceToString(v),
					Network: false,
					Type:    "v4",
					Time:    time.Now().Unix(),
				})
			}
			if public.IsIpNetwork(public.InterfaceToString(v)) {
				fileData[name] = append(fileData[name], types.Group{
					IP:      public.InterfaceToString(v),
					Network: true,
					Type:    "v4",
					Time:    time.Now().Unix(),
				})
			}
		}
		ipSet[public.InterfaceToString(v)] = nil
	}
	return fileData, nil
}

func (ip *Inset) IpList(request *http.Request) core.Response {
	fileData, err := ip.rFile(ip.ipData)
	if err != nil {
		return core.Fail(err)
	}
	result := make(map[string][]string)
	for key, value := range fileData {
		result[key] = make([]string, 0)
		for _, v := range value {
			result[key] = append(result[key], v.IP)
		}
	}
	return core.Success(result)
}

func (ip *Inset) IpNameList(request *http.Request) core.Response {
	fileData, err := ip.rFile(ip.ipData)
	if err != nil {
		return core.Fail(err)
	}
	result := make([]string, 0)
	for key := range fileData {
		result = append(result, key)
	}

	return core.Success(result)
}

func (ip *Inset) readIpData(path string) ([][]interface{}, error) {
	jsonData, err := public.ReadFile(path)
	if err != nil {
		jsonData = string([]byte("[]"))
	}
	fileData := make([][]interface{}, 0)
	err = json.Unmarshal([]byte(jsonData), &fileData)
	if err != nil {
		return nil, err
	}
	return fileData, nil
}

func (ip *Inset) readMenData(name string) bool {
	path := "/www/cloud_waf/nginx/conf.d/waf/rule/cc.json"
	filedata, err := public.ReadFile(path)
	if err != nil {
		return false
	}
	data_ := make([]struct {
		RuleLog string `json:"rule_log"`
	}, 0)

	err = json.Unmarshal([]byte(filedata), &data_)
	if err != nil {
		return false
	}
	key := fmt.Sprintf(core.Lan("modules.ip_group.match_ip_group"), name)
	for _, v := range data_ {
		if strings.Contains(v.RuleLog, key) {
			return true
		}
	}
	return false
}

func (ip *Inset) GetMaliciousIpList(request *http.Request) core.Response {
	params := struct {
		P       int    `json:"p"`
		Psize   int    `json:"p_size"`
		Sort    int    `json:"sort"`
		Keyword string `json:"keyword"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.P == 0 {
		params.P = 1
		params.Psize = 1000000
	}
	jsonData, err := public.ReadFile(public.MALICIOUS_IP_FILE)
	if err != nil {
		jsonData = string([]byte("[]"))
	}
	type ipInfo struct {
		ReleaseTime int64 `json:"release_time"`
	}
	var ipInfoMap map[string]ipInfo
	err = json.Unmarshal([]byte(jsonData), &ipInfoMap)
	if err != nil {
		return core.Fail(err)
	}
	var maliciousIpList []map[string]interface{}
	for k, v := range ipInfoMap {
		if params.Keyword != "" && !strings.Contains(k, params.Keyword) {
			continue
		}
		maliciousIpList = append(maliciousIpList, map[string]interface{}{"ip": k, "release_time": v.ReleaseTime})
	}
	switch params.Sort {
	case 1:
		sort.Slice(maliciousIpList, func(i, j int) bool {
			return public.InterfaceToString(maliciousIpList[i]["ip"]) < public.InterfaceToString(maliciousIpList[j]["ip"])
		})
	case 2:
		sort.Slice(maliciousIpList, func(i, j int) bool {
			return public.InterfaceToString(maliciousIpList[i]["ip"]) > public.InterfaceToString(maliciousIpList[j]["ip"])
		})
	case 3:
		sort.Slice(maliciousIpList, func(i, j int) bool {
			return public.InterfaceToInt64(maliciousIpList[i]["release_time"]) > public.InterfaceToInt64(maliciousIpList[j]["release_time"])
		})
	case 4:
		sort.Slice(maliciousIpList, func(i, j int) bool {
			return public.InterfaceToInt64(maliciousIpList[i]["release_time"]) > public.InterfaceToInt64(maliciousIpList[j]["release_time"])
		})
	}
	start := (params.P - 1) * params.Psize
	end := start + params.Psize - 1
	if start > len(maliciousIpList) {
		return core.Success(nil)
	} else {
		if end > len(maliciousIpList) {
			end = len(maliciousIpList)
		}
		maliciousIpList = maliciousIpList[start:end]
	}
	if len(maliciousIpList) == 0 {
		maliciousIpList = append(maliciousIpList, map[string]interface{}{"ip": "1.63.41.100", "release_time": 1750065975})
		return core.Success(maliciousIpList)
	}
	return core.Success(maliciousIpList)
}
