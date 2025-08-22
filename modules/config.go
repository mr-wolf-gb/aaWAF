package modules

import (
	"CloudWaf/core"
	"CloudWaf/core/jwt"
	"CloudWaf/core/language"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/public/db"
	"CloudWaf/public/validate"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func init() {

	core.RegisterModule(&Config{
		cert_path:   core.AbsPath("./ssl/certificate.pem"),
		key_path:    core.AbsPath("./ssl/privateKey.pem"),
		config_path: core.AbsPath("./config/sysconfig.json"),
		two_auth:    core.AbsPath("./config/two_auth.json"),
		basic_auth:  "./config/basic_auth.json",
		port:        core.AbsPath("./data/.server-port"),
		logoPath:    core.AbsPath("./config/logo.txt"),
		blockPage:   "/www/cloud_waf/nginx/conf.d/waf/html/black.html",
	})
}

type Config struct {
	cert_path   string
	key_path    string
	config_path string
	two_auth    string
	basic_auth  string
	port        string
	logoPath    string
	blockPage   string
}

func (config *Config) GetConfig(request *http.Request) core.Response {
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	times := time.Now().Unix()
	data["cur_time"] = times
	if data["worker"] == nil {
		data["worker"] = true
	}
	if data["warning_open"] == nil {
		data["warning_open"] = true
	}
	if data["interceptPage"] == nil {
		data["interceptPage"] = core.Lan("modules.config.intercept_page.default")
	}

	data["interceptPage"] = html.UnescapeString(data["interceptPage"].(string))
	response, _ := public.SqliteWithClose(func(conn *db.Sqlite) (interface{}, error) {
		userInfo, err := conn.NewQuery().
			Table("users").
			Where("id = ?", []interface{}{uid}).
			Field([]string{"pwd_update_time"}).
			Find()

		if err != nil {
			logging.Info(core.Lan("modules.config.get_user_info.fail"), err)
		}
		data["password_expire_time"] = public.InterfaceToInt(userInfo["pwd_update_time"]) + public.InterfaceToInt(data["password_expire"])*86400
		return userInfo, nil
	})

	if response == nil {
		return core.Fail(core.Lan("modules.config.get_pwd_update_time.fail"))
	}
	twoAuth, err := public.Rconfigfile(config.two_auth)
	if err != nil {
		return core.Fail(err)
	}

	status := public.InterfaceToBool(twoAuth["open"])
	basicAuth, err := public.Rconfigfile(config.basic_auth)
	if err != nil {
		return core.Fail(err)
	}
	s := time.Now().String()
	systemTime := s[:19] + " " + s[30:39]
	apiinfo, err := public.GetWAFApi()
	syslogConfig, _ := public.ReadSyslogConfig()

	return core.Success(map[string]interface{}{
		"config":        data,
		"port":          core.GetServerPort(),
		"two_step_auth": status,
		"basic_auth":    basicAuth,
		"systemdate":    systemTime,
		"apiinfo":       apiinfo,
		"syslog":        syslogConfig,
	})
}

// 开启API
func (config *Config) SetOpenApi(request *http.Request) core.Response {
	params := struct {
		Type      int    `json:"type"`
		LimitAddr string `json:"limit_addr"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	// t_type 类型 1 重置Token
	// t_type 类型 2  开启或者关闭API
	// t_type 类型 3  设置地址
	//limit_addr  限制地址
	t_type := params.Type
	limit_addr := params.LimitAddr
	if params.Type == 3 {
		// 判断
		apiinfo, _ := public.GetWAFApi()
		limit_addr_arr := strings.Split(limit_addr, "\n")
		apiinfo.LimitAddr = limit_addr_arr
		public.SaveWAFApi(apiinfo)
		return core.Success(core.Lan("modules.config.set.success"))
	}
	if t_type == 2 {
		apiinfo, _ := public.GetWAFApi()
		if apiinfo.Open == false && apiinfo.Token == "" {
			apiinfo.Token = public.RandomStr(32)
			apiinfo.Open = true
			public.SaveWAFApi(apiinfo)
			return core.Success(core.Lan("modules.config.set.success"))
		}
		if apiinfo.Open == true {
			apiinfo.Open = false
			apiinfo.Token = ""
			public.SaveWAFApi(apiinfo)
			return core.Success(core.Lan("modules.config.set.success"))
		} else {
			apiinfo.Open = true
			apiinfo.Token = public.RandomStr(32)
			public.SaveWAFApi(apiinfo)
			return core.Success(core.Lan("modules.config.set.success"))
		}
	}
	if t_type == 1 {
		apiinfo, _ := public.GetWAFApi()
		apiinfo.Token = public.RandomStr(32)
		public.SaveWAFApi(apiinfo)
		return core.Success(core.Lan("modules.config.set.success"))
	}

	return core.Success(core.Lan("modules.config.set.success"))

}

func (config *Config) SetCert(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	if _, ok := params["certContent"]; !ok {
		return core.Fail(core.Lan("modules.config.cert_content.empty"))
	}
	if _, ok := params["keyContent"]; !ok {
		return core.Fail(core.Lan("modules.config.cert_key.empty"))
	}
	public.WriteFile(config.cert_path, params["certContent"].(string))
	public.WriteFile(config.key_path, params["keyContent"].(string))
	go func() {
		time.Sleep(10 * time.Millisecond)
		_, err = public.ExecCommandCombined("bash", "-c", "cat /www/cloud_waf/console/data/.pid |xargs kill -9;nohup /www/cloud_waf/console/CloudWaf >> /www/cloud_waf/console/logs/error.log 2>&1 &")
	}()
	public.WriteOptLog(fmt.Sprintf(core.Lan("modules.config.cert_set.success")), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success(core.Lan("modules.config.cert_set.success"))
}

// 重新生成证书
func (config *Config) NewGenerateCertificate(request *http.Request) core.Response {
	serverIp, localIp := core.GetServerIp()
	pfxFile := core.AbsPath("./ssl/baota_root.pfx")
	pfxPwdFile := core.AbsPath("./ssl/root_password.pl")
	data := map[string]any{
		"action":     "get_domain_cert",
		"company":    "宝塔面板",
		"panel":      1,
		"uid":        0,
		"access_key": strings.Repeat("B", 32),
		"domain":     serverIp + "," + localIp,
	}
	client := public.GetHttpClient(60)
	bs, err := json.Marshal(data)
	if err != nil {
		return core.Fail(err)
	}
	dataValues, err := url.ParseQuery("data=" + string(bs))
	if err != nil {
		return core.Fail(err)
	}
	resp, err := client.PostForm("https://api.bt.cn/bt_cert", dataValues)
	if err != nil {
		return core.Fail(err)
	}
	defer resp.Body.Close()
	resultBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return core.Fail(err)
	}
	if resp.StatusCode != http.StatusOK {
		return core.Fail(core.Lan("modules.config.new_cert.fail"))
	}
	m := struct {
		Status   bool   `json:"status"`
		Cert     string `json:"cert"`
		Key      string `json:"key"`
		Pfx      string `json:"pfx"`
		Password string `json:"password"`
		Msg      string `json:"msg"`
	}{}
	if err = json.Unmarshal(resultBytes, &m); err != nil {
		return core.Fail(err)
	}
	if !m.Status {
		return core.Fail(core.Lan("modules.config.new_cert.fail.with_msg") + m.Msg)
	}

	if err := os.WriteFile(config.cert_path, []byte(m.Cert), fs.ModePerm); err != nil {
		return core.Fail(err)
	}

	if err := os.WriteFile(config.key_path, []byte(m.Key), fs.ModePerm); err != nil {
		return core.Fail(err)
	}

	pfxBs, err := base64.StdEncoding.DecodeString(m.Pfx)

	if err != nil {
		return core.Fail(err)
	}

	if err := os.WriteFile(pfxFile, pfxBs, fs.ModePerm); err != nil {
		return core.Fail(err)
	}

	if err := os.WriteFile(pfxPwdFile, []byte(m.Password), fs.ModePerm); err != nil {
		return core.Fail(err)
	}
	go func() {
		time.Sleep(10 * time.Millisecond)
		_, err = public.ExecCommandCombined("bash", "-c", "cat /www/cloud_waf/console/data/.pid |xargs kill -9;nohup /www/cloud_waf/console/CloudWaf >> /www/cloud_waf/console/logs/error.log 2>&1 &")
	}()

	return core.Success(core.Lan("modules.config.new_cert.success"))
}
func (config *Config) GetCert(request *http.Request) core.Response {
	cert_pem, err := public.ReadFile(config.cert_path)
	if err != nil {
		return core.Fail(err)
	}
	key_pem, err := public.ReadFile(config.key_path)
	if err != nil {
		return core.Fail(err)
	}
	return core.Success(map[string]interface{}{
		"cert_pem": cert_pem,
		"key_pem":  key_pem,
	})
}

func (config *Config) SetPort(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := params["port"]; !ok {
		return core.Fail(core.Lan("modules.config.port.empty"))
	}
	number := public.InterfaceToInt(params["port"])
	if number < 1 || number > 65535 {
		return core.Fail(core.Lan("modules.config.port_range.error"))
	}
	if err != nil {
		return core.Fail(err)
	}
	if public.CheckPort(number) {
		err := public.AllowPort(strconv.Itoa(number))
		if err != nil {
			return nil
		}
		oldPort, err := public.ReadFile(config.port)
		if err != nil {
			return core.Fail(err)
		}
		if oldPort != strconv.Itoa(number) {
			err := public.DeletePort(strings.Trim(oldPort, "\n"))
			if err != nil {
				return nil
			}
		}
	} else {
		return core.Success(core.Lan("modules.config.port_occupied"))
	}
	_, err = public.WriteFile(config.port, strconv.Itoa(number))
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf(core.Lan("modules.config.port_set.success")), public.OPT_LOG_TYPE_SYSTEM, uid)
	go func() {
		time.Sleep(10 * time.Millisecond)
		_, err = public.ExecCommandCombined("bash", "-c", "cat /www/cloud_waf/console/data/.pid |xargs kill -9;nohup /www/cloud_waf/console/CloudWaf >> /www/cloud_waf/console/logs/error.log 2>&1 &")
	}()

	return core.Success(core.Lan("modules.config.port_set.success"))
}

func (config *Config) SetIp(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	acceptIp := []string{}
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	accept_ip := params["accept_ip"].(string)
	if _, err := params["accept_ip"]; err {
		if accept_ip != "" {
			for _, ip := range strings.Split(accept_ip, ",") {
				ip = strings.TrimSpace(ip)
				if !public.IsIpAddr(ip) {
					return core.Fail(core.Lan("modules.config.ip_format.invalid"))
				}
				if !config.stringInSlice(ip, acceptIp) {
					acceptIp = append(acceptIp, ip)
				}
			}
			data["accept_ip"] = acceptIp
		} else {
			data["accept_ip"] = make([]string, 0)
		}

	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf(core.Lan("modules.config.auth_ip_set.success")), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success(core.Lan("modules.config.auth_ip_set.success"))
}

func (config *Config) stringInSlice(str string, slice []string) bool {
	for _, s := range slice {
		if strings.HasPrefix(s, str) {
			return true
		}
	}
	return false
}

func (config *Config) SetDomain(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)

	if err != nil {
		return core.Fail(err)
	}

	uid := token.Uid()
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := params["accept_domain"]; ok {
		domain := params["accept_domain"].(string)
		if domain != "" {
			if !validate.IsHost(params["accept_domain"].(string)) {
				return core.Fail(core.Lan("modules.config.domain_format.invalid"))
			} else {
				data["accept_domain"] = params["accept_domain"]
			}
		} else {
			data["accept_domain"] = ""
		}
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf(core.Lan("modules.config.domain_set.success")), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success(core.Lan("modules.config.bind_domain_set.success"))
}

func (config *Config) Setntp(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	status := false
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["open"]; ok {
		switch public.InterfaceToInt(params["open"]) {
		case 1:
			data["ntptime"] = true
			status = true
		case 0:
			data["ntptime"] = false
		default:
			return core.Fail(core.Lan("modules.config.param.invalid"))
		}
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}

	status_msg := core.Lan("modules.config.close")
	if status {
		status_msg = core.Lan("modules.config.open")
	}
	public.WriteOptLog(fmt.Sprintf("%s时间同步设置", status_msg), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success(core.Lan("modules.config.time_sync_set.success"))
}

func (config *Config) SetTimeout(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)

	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()

	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["session_timeout"]; !ok {
		return core.Fail(core.Lan("modules.config.session_timeout.empty"))
	}
	timeout := params["session_timeout"]
	if public.InterfaceToInt(timeout) < 0 {
		return core.Fail(core.Lan("modules.config.session_timeout.invalid"))
	}
	if timeout == nil || public.InterfaceToInt(timeout) == 0 {
		data["session_timeout"] = 120
	} else {
		data["session_timeout"] = public.InterfaceToInt(timeout)
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf(core.Lan("modules.config.session_timeout_set.success")), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success(core.Lan("modules.config.session_timeout_set.success"))
}

func (config *Config) SetBasicAuth(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	data, err := public.Rconfigfile(config.basic_auth)
	if err != nil {
		return core.Fail(err)
	}
	isopen := false
	if _, ok := params["open"]; ok {
		switch public.InterfaceToInt(params["open"]) {
		case 1:
			data["open"] = true
			isopen = true
			basicUser := strings.TrimSpace(params["basic_user"].(string))
			if basicUser == "" {
				return core.Fail(core.Lan("modules.config.username.empty"))
			}
			basicPwd := strings.TrimSpace(params["basic_pwd"].(string))
			if basicPwd == "" {
				return core.Fail(core.Lan("modules.config.password.empty"))
			}

			data["basic_user"], err = public.StringMd5(basicUser)
			if err != nil {
				return core.Fail(core.Lan("modules.config.username_encrypt.fail"))
			}
			data["basic_pwd"], err = public.StringMd5(basicPwd)
			if err != nil {
				return core.Fail(core.Lan("modules.config.password_encrypt.fail"))
			}
		case 0:
			data["open"] = false
		default:
			return core.Fail(core.Lan("modules.config.param.invalid"))
		}
	}
	err = public.Wconfigfile(config.basic_auth, data)
	if err != nil {
		return core.Fail(err)
	}

	status_msg := core.Lan("modules.config.close")
	if isopen {
		status_msg = core.Lan("modules.config.open")
	}

	public.WriteOptLog(fmt.Sprintf("%sBasicAuth设置", status_msg), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success(core.Lan("modules.config.basic_auth_set.success"))
}

func (config *Config) SetTwoAuth(request *http.Request) core.Response {
	params := struct {
		Open   int    `json:"open"`
		Secret string `json:"secret_key"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}

	token, err := jwt.ParseTokenWithRequest(request)

	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()

	data, err := public.Rconfigfile(config.two_auth)
	if err != nil {
		return core.Fail(err)
	}
	isopen := false
	if params.Open != 0 {
		switch public.InterfaceToInt(params.Open) {
		case 1:
			data["open"] = true
			isopen = true
			username := public.RandomStr(8)
			data["username"] = username
			serverIp, localIp := core.GetServerIp()

			if serverIp == "127.0.0.1" {
				serverIp = localIp
			}

			if len(params.Secret) < 16 {
				potp, err := totp.Generate(totp.GenerateOpts{
					Issuer:      "BTWAF--" + serverIp,
					AccountName: username,
				})
				if err != nil {
					return core.Fail(err)
				}
				data["secret_key"] = potp.Secret()
				data["qrcode_url"] = potp.URL()

			} else {
				potp, err := totp.Generate(totp.GenerateOpts{
					Issuer:      "BTWAF--" + serverIp,
					AccountName: username,
					Secret:      []byte(params.Secret),
				})
				if err != nil {
					return core.Fail(err)
				}
				data["secret_key"] = potp.Secret()
				data["qrcode_url"] = potp.URL()
			}
		case 0:
			data["open"] = false
		default:
			return core.Fail(core.Lan("modules.config.param.invalid"))
		}
	}

	if params.Open == 0 {
		data["open"] = false
	} else if params.Open == 1 {

		data["open"] = true
		isopen = true
		username := public.RandomStr(8)
		data["username"] = username
		serverIp, localIp := core.GetServerIp()

		if serverIp == "127.0.0.1" {
			serverIp = localIp
		}
		if len(params.Secret) < 16 {
			potp, err := totp.Generate(totp.GenerateOpts{
				Issuer:      "BTWAF--" + serverIp,
				AccountName: username,
			})
			if err != nil {
				return core.Fail(err)
			}
			data["secret_key"] = potp.Secret()
			data["qrcode_url"] = potp.URL()

		} else {
			potp, err := totp.Generate(totp.GenerateOpts{
				Issuer:      "BTWAF--" + serverIp,
				AccountName: username,
				Secret:      []byte(params.Secret),
			})

			if err != nil {
				return core.Fail(err)
			}
			data["qrcode_url"] = potp.URL()
		}
	} else {
		return core.Fail(core.Lan("modules.config.param.invalid"))
	}
	err = public.Wconfigfile(config.two_auth, data)
	if err != nil {
		return core.Fail(err)
	}
	status_msg := core.Lan("modules.config.close")
	if isopen {
		status_msg = core.Lan("modules.config.open")
	}
	go func() {
		time.Sleep(10 * time.Millisecond)
		_, err = public.ExecCommandCombined("bash", "-c", "cat /www/cloud_waf/console/data/.pid |xargs kill -9;nohup /www/cloud_waf/console/CloudWaf >> /www/cloud_waf/console/logs/error.log 2>&1 &")
	}()

	public.WriteOptLog(fmt.Sprintf("%s动态口令认证设置", status_msg), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success(core.Lan("modules.config.2fa_set.success"))
}

func (config *Config) CheckTwoAuth(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	data, err := public.Rconfigfile(config.two_auth)
	if err != nil {
		return core.Fail(err)
	}
	secret := public.InterfaceToString(data["secret_key"])
	passcode := public.InterfaceToString(params["passcode"])
	if data["open"] == true {
		check, err := totp.ValidateCustom(
			passcode,
			secret,
			time.Now().UTC(),
			totp.ValidateOpts{
				Period:    30,
				Skew:      1,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			},
		)

		if err != nil {
			return core.Fail(err)
		}
		if check == true {
			return core.Success(core.Lan("modules.config.auth.success"))
		} else {
			return core.Fail(core.Lan("modules.config.auth.fail"))
		}
	}
	return core.Fail(core.Lan("modules.config.2fa_not_open"))
}

func (config *Config) GetTwoAuth(request *http.Request) core.Response {
	data, err := public.Rconfigfile(config.two_auth)
	if err != nil {
		return core.Fail(err)
	}
	return core.Success(data)
}

func (config *Config) SetPwd(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	pwd_complexity := false
	if val, ok := params["password_complexity"]; ok {
		switch public.InterfaceToInt(val) {
		case 1:
			pwd_complexity = true
			data["password_complexity"] = true
		case 0:
			data["password_complexity"] = false
		default:
			return core.Fail(core.Lan("modules.config.param.invalid"))
		}
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	status_msg := core.Lan("modules.config.close")
	if pwd_complexity {
		status_msg = core.Lan("modules.config.open")
	}

	public.WriteOptLog(fmt.Sprintf("%s密码复杂度验证", status_msg), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success(core.Lan("modules.config.pwd_complexity_set.success"))
}

func (config *Config) SetPwdExpire(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)

	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["password_expire"]; !ok {
		return core.Fail(core.Lan("modules.config.pwd_expire.missing"))
	}
	if public.InterfaceToInt(params["password_expire"]) < 0 {
		return core.Fail(core.Lan("modules.config.pwd_expire.invalid"))
	}

	data["password_expire"] = public.InterfaceToInt(params["password_expire"])
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf(core.Lan("modules.config.pwd_expire_set.success")), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success(core.Lan("modules.config.pwd_expire_set.success"))
}

func (config *Config) SetAdminPath(request *http.Request) core.Response {

	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)

	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["admin_path"]; ok {
		adminPath := params["admin_path"].(string)
		if len(adminPath) < 8 {
			return core.Fail(core.Lan("modules.config.auth_path.least_8_chars"))
		}
		if !validate.IsAdminPath(adminPath) {
			return core.Fail(core.Lan("modules.config.auth_path.incorrect_format"))
		}
		data["admin_path"] = "/" + adminPath
	} else {
		data["admin_path"] = ""
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf(core.Lan("modules.config.auth_path_set.success")), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success(core.Lan("modules.config.auth_path_set.success"))
}

func (config *Config) SyncDate(request *http.Request) core.Response {
	uid := public.GetUid(request)
	resp, err := public.HttpGet("https://www.bt.cn/api/index/get_time", 6)
	if err != nil {
		return core.Fail(core.Lan("modules.config.conn_time_server.fail"))
	}
	body, err := strconv.Atoi(resp)
	if err != nil {
		return core.Fail(core.Lan("modules.config.conn_time_server.fail"))
	}
	timeStr := strings.TrimSpace(strconv.Itoa(body))
	newTime, err := strconv.ParseInt(timeStr, 10, 64)
	if err != nil {
		return core.Fail(core.Lan("modules.config.conn_time_server.fail"))
	}

	newTime -= 28800
	addTime, err := exec.Command("date", `+%z`).Output()
	if err != nil {
		return core.Fail(core.Lan("modules.config.get_current_timezone.fail"))
	}
	addTimeStr := strings.TrimSpace(string(addTime))
	add1 := false
	if addTimeStr[0] == '+' {
		add1 = true
	}
	addV, err := strconv.Atoi(addTimeStr[1 : len(addTimeStr)-2])
	if err != nil {
		return core.Fail(core.Lan("modules.config.parse_timezone_offset.fail"))
	}
	num, _ := strconv.Atoi(addTimeStr[len(addTimeStr)-2:])

	addV = addV*3600 + num*60

	if add1 {
		newTime += int64(addV)
	} else {
		newTime -= int64(addV)
	}
	dateStr := time.Unix(newTime, 0).Format("2006-01-02 15:04:05")
	cmd := exec.Command("date", "-s", dateStr)
	err = cmd.Run()
	if err != nil {
		return core.Fail(core.Lan("modules.config.set_server_time.fail"))
	}
	public.WriteOptLog(fmt.Sprintf(core.Lan("modules.config.sync_server_time.success")), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success(core.Lan("modules.config.sync_server_time.success"))
}

func (config *Config) SetHelp(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)

	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	status := false
	if val, ok := params["open"]; ok {
		switch public.InterfaceToInt(val) {
		case 1:
			status = true
			data["worker"] = true
		case 0:
			data["worker"] = false
		default:
			return core.Fail(core.Lan("modules.config.param.invalid"))
		}
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}

	status_msg := core.Lan("modules.config.close")
	if status {
		status_msg = core.Lan("modules.config.open")
	}

	public.WriteOptLog(fmt.Sprintf("%s在线客服设置成功", status_msg), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success(core.Lan("modules.config.online_service_set.success"))
}

func (config *Config) SetTitle(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	if _, ok := params["title"]; !ok {
		return core.Fail(core.Lan("modules.config.title.missing"))
	}

	if _, ok := params["logo"]; !ok {
		return core.Fail(core.Lan("modules.config.logo.missing"))
	}
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := params["title"]; ok {
		data["title"] = params["title"].(string)
	} else {
		data["title"] = ""
	}

	_, err = os.Stat(config.logoPath)
	if err != nil {
		file, err := os.Create(config.logoPath)
		if err != nil {
			return core.Fail(err)
		}
		defer file.Close()
	}

	logoData := []byte(public.InterfaceToString(params["logo"]))
	if float64(len(logoData))*0.7 > 100*1024 {
		return core.Success(core.Lan("modules.config.logo_size.exceed"))
	}
	_, err = public.WriteFile(config.logoPath, params["logo"].(string))
	if nil != err {
		return core.Fail(err)
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}

	public.WriteOptLog(fmt.Sprintf(core.Lan("modules.config.corp_name_set.success"), params["title"].(string)), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success(core.Lan("modules.config.set.success"))
}

func (config *Config) Title(request *http.Request) core.Response {
	data, err := public.Rconfigfile(core.AbsPath("./config/sysconfig.json"))
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := data["title"]; !ok {
		data["title"] = core.Lan("modules.config.default_waf_title")
	}
	_, err = os.Stat(config.logoPath)
	if err != nil {
		file, err := os.Create(config.logoPath)
		if err != nil {
			return core.Fail(err)
		}
		defer file.Close()
	}

	logoData, err := public.ReadFile(config.logoPath)
	if err != nil {
		return core.Fail(err)
	}
	au, _ := core.Auth()

	status := true
	if au.Auth.Extra.Type == 0 {
		status = false
	}

	return core.Success(map[string]interface{}{
		"title":  data["title"],
		"logo":   logoData,
		"status": status,
	})
}

func (config *Config) SetWarningOpen(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["warning_open"]; !ok {
		return core.Fail(core.Lan("modules.config.warning_open.missing"))
	}

	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	warning_open := false
	if val, ok := params["warning_open"]; ok {
		switch public.InterfaceToInt(val) {
		case 1:
			warning_open = true
			data["warning_open"] = true
		case 0:
			data["warning_open"] = false
		default:
			return core.Fail(core.Lan("modules.config.param.invalid"))
		}
	}
	status_msg := core.Lan("modules.config.close")
	if warning_open {
		status_msg = core.Lan("modules.config.open")
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf(core.Lan("modules.config.warning_set.success"), status_msg), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success(fmt.Sprintf(core.Lan("modules.config.global_warning_set.success"), status_msg))

}

func (config *Config) SetInterceptPage(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := params["data"]; !ok {
		return core.Fail(core.Lan("modules.config.data.missing"))
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	au, _ := core.Auth()

	if au.Auth.Extra.Type == 0 {
		return core.Success(core.Lan("modules.config.free_version_no_intercept_page"))
	}
	content, err := public.ReadFile("/www/cloud_waf/nginx/conf.d/waf/html/black.html")

	if _, ok := params["type"]; ok && params["type"] == "logo" {
		logo := regexp.MustCompile(`(<image[^>]+?xlink:href=")[^"]+`)
		logoData, err := public.ReadFile(config.logoPath)
		if err != nil {
			return core.Fail(err)
		}
		content = html.UnescapeString(logo.ReplaceAllString(content, "${1}"+logoData))
	}
	reg := regexp.MustCompile(`(?s)(<div class=\"desc\">).*?(</div>)`)
	content = reg.ReplaceAllString(content, "${1}"+html.UnescapeString(params["data"].(string))+"${2}")
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}

	data["interceptPage"] = params["data"].(string)
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteFile("/www/cloud_waf/nginx/conf.d/waf/html/black.html", content)
	public.WriteOptLog(fmt.Sprintf(core.Lan("modules.config.intercept_page_set.success")), public.OPT_LOG_TYPE_SYSTEM, uid)
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=config", 2)
	return core.Success(core.Lan("modules.config.set.success"))
}

func (config *Config) SetLanguage(request *http.Request) core.Response {
	params := struct {
		Lan string `json:"lan"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.Lan == "" {
		return core.Fail(core.Lan("modules.config.lang_type.empty"))
	}
	if !public.InArray(params.Lan, language.VALID_LANGUAGE) {
		return core.Fail(core.Lan("modules.config.lang_type.invalid") + params.Lan)
	}
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	data["language"] = params.Lan
	if err := public.Wconfigfile(config.config_path, data); err != nil {
		return core.Fail(err)
	}

	return core.Success(core.Lan("modules.config.op.success"))
}

func (config *Config) SetSyslog(request *http.Request) core.Response {
	params := struct {
		Open bool   `json:"open"` // 是否开启Syslog
		Host string `json:"host"` // Syslog服务器地址
		Port int    `json:"port"` // Syslog服务器端口
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}

	if params.Host == "" {
		return core.Fail(core.Lan("modules.config.syslog_host.empty"))
	}
	if !validate.IsHost(params.Host) {
		return core.Fail(core.Lan("modules.config.syslog_host.invalid"))
	}
	if params.Port < 1 || params.Port > 65535 {
		return core.Fail(core.Lan("modules.config.syslog_port.invalid"))
	}
	err := public.SetSysLog(params.Open, params.Host, params.Port)
	if err != nil {
		return core.Fail(err)
	}
	return core.Success(core.Lan("modules.config.op.success"))

}
