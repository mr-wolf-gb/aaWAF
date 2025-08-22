package modules

import (
	"CloudWaf/core"
	"CloudWaf/core/authorization"
	"CloudWaf/core/cache"
	"CloudWaf/core/jwt"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	clusterCommon "CloudWaf/public/cluster_core/common"
	"CloudWaf/public/db"
	"CloudWaf/types"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func init() {
	core.RegisterModule(&User{})
}

type User struct{}

func (user *User) Login(request *http.Request) core.Response {
	maxRetries := 5
	blockTime := 300
	params := struct {
		Username       string `json:"username"`
		Password       string `json:"password"`
		ValidateCode   string `json:"validate_code"`
		ValidateCodeId string `json:"validate_code_id"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.Username == "" {
		return core.Fail(core.Lan("user.login.param.username.empty"))
	}
	if params.Password == "" {
		return core.Fail(core.Lan("user.login.param.password.empty"))
	}
	validateSuccess := true
	loginSuccessFlag := false
	clientIp := core.GetClientIpFromRequest(request)
	cacheKey := fmt.Sprintf("USER_LOGIN_RETRIES:%s", clientIp)
	loginRetries := 0
	if cache.Has(cacheKey) {
		if v, ok := cache.Get(cacheKey).(int); ok {
			loginRetries = v
		}
	}
	defer func() {
		if !validateSuccess {
			return
		}
		if loginSuccessFlag {
			cache.Remove(cacheKey)
			return
		}
		cache.Set(cacheKey, loginRetries+1, 300)
		public.WriteOptLog(core.Lan("user.login.opt_log.fail", clientIp, public.GetIPAreaBrief(clientIp)), public.OPT_LOG_TYPE_LOGIN_FAIL, 0)
	}()

	if loginRetries >= maxRetries {
		k := "USER_LOGIN_RETRIES_RELEASE_TIME:" + clientIp
		if !cache.Has(k) {
			cache.Set(k, time.Now().Unix()+int64(blockTime), int64(blockTime))
		}
		if releaseTime, ok := cache.Get(k).(int64); ok {
			return core.Fail(core.Lan("user.login.fail.too_many", time.Now().Unix()-releaseTime))
		}
		return core.Fail(core.Lan("user.login.fail.too_many", blockTime))
	}
	if cache.Has(cacheKey) {
		validateSuccess = false
		if params.ValidateCode == "" {
			return core.Fail(core.Lan("user.login.param.validate_code.empty"))
		}
		if params.ValidateCodeId == "" {
			return core.Fail(core.Lan("user.login.param.validate_code_id.empty"))
		}

		validateCodeCacheKey := fmt.Sprintf("USER_LOGIN_VALIDATE_CODE:%s", params.ValidateCodeId)
		if !cache.Has(validateCodeCacheKey) {
			return core.Fail(core.Lan("user.login.validate_code.expire"))
		}
		if !strings.EqualFold(cache.Get(validateCodeCacheKey).(string), params.ValidateCode) {
			cache.Remove(validateCodeCacheKey)
			return core.Fail(core.Lan("user.login.validate_code.incorrect"))
		}
		cache.Remove(validateCodeCacheKey)
		validateSuccess = true
	}

	userInfo := struct {
		Id            int    `json:"id"`
		Md5Passwd     string `json:"md5_passwd"`
		Salt          string `json:"salt"`
		PwdUpdateTime int    `json:"pwd_update_time"`
	}{}

	if err := public.S("users").
		Where("username = ?", []any{params.Username}).
		Field([]string{"id", "md5_passwd", "salt", "pwd_update_time"}).
		FindAs(&userInfo); err != nil {
		return core.Fail(core.Lan("user.login.incorrect", maxRetries-loginRetries-1))
	}
	saltedPasswd, err := public.StringMd5WithSalt(params.Password, userInfo.Salt)
	if err != nil || userInfo.Md5Passwd != saltedPasswd {
		return core.Fail(core.Lan("user.login.incorrect", maxRetries-loginRetries-1))
	}
	loginTime := int(time.Now().Unix())
	data, err := public.Rconfigfile("./config/sysconfig.json")

	if err == nil {
		expireDays := public.InterfaceToInt(data["password_expire"])
		if expireDays > 0 {
			expiredTime := userInfo.PwdUpdateTime + expireDays*86400
			if loginTime > expiredTime {
				return core.Fail(core.Lan("user.login.password.expire", maxRetries-loginRetries-1))
			}
		}
	}
	if public.GetTwoAuth() {
		return core.Success(map[string]interface{}{
			"two_auth": true,
		})
	}
	token, err := jwt.BuildToken(strconv.Itoa(userInfo.Id))

	if err != nil {
		return core.Fail(err)
	}

	loginSuccessFlag = true
	public.WriteOptLog(core.Lan("user.login.opt_log.success", clientIp, public.GetIPAreaBrief(clientIp)), public.OPT_LOG_TYPE_LOGIN_SUCCESS, token.Uid())
	core.SetSession(request, "IsLogin", true)

	return core.Success(map[string]interface{}{
		"prefix": jwt.PREFIX,
		"token":  token.String(),
		"ttl":    jwt.TTL() * 60,
	})
}

func (user *User) CheckTwoAuth(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["code"]; !ok {
		return core.Fail(core.Lan("user.login.param.validate_code.empty"))
	}
	loginCode := public.InterfaceToString(params["code"])
	if !public.CheckTwoAuth(loginCode) {
		return core.Fail(core.Lan("user.two_auth.validate.fail"))
	}
	clientIp := core.GetClientIpFromRequest(request)
	token, err := jwt.BuildToken(strconv.Itoa(1))

	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(core.Lan("user.login.opt_log.success", clientIp, public.GetIPAreaBrief(clientIp)), public.OPT_LOG_TYPE_LOGIN_SUCCESS, token.Uid())
	return core.Success(map[string]interface{}{
		"prefix": jwt.PREFIX,
		"token":  token.String(),
		"ttl":    jwt.TTL() * 60,
	})
}

func (user *User) Refresh(request *http.Request) core.Response {
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	newToken, err := token.Refresh()
	if err != nil {
		return core.Fail(err)
	}
	core.SetSession(request, "IsLogin", true)
	return core.Success(map[string]interface{}{
		"prefix": jwt.PREFIX,
		"token":  newToken.String(),
		"ttl":    jwt.TTL() * 60,
	})
}

func (user *User) Logout(request *http.Request) core.Response {
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	err = token.Invalidate()

	if err != nil {
		return core.Fail(err)
	}
	core.SetSession(request, "IsLogin", false)
	public.WriteOptLog(core.Lan("user.logout.opt_log.success"), public.OPT_LOG_TYPE_LOGOUT, token.Uid())
	return core.Success(core.Lan("user.logout.success"))
}

func (user *User) GetValidateCode(request *http.Request) core.Response {
	CodeResult := public.SetCodeResult(1, time.Microsecond*1)
	id, imgBase64, err := public.CreatStringCode(nil, CodeResult)
	if err != nil {
		return core.Fail(core.Lan("user.generate_code.fail"))
	}
	err = cache.Set(fmt.Sprintf("USER_LOGIN_VALIDATE_CODE:%s", id), public.GetCode(CodeResult, id), 120)

	if err != nil {
		return core.Fail(core.Lan("user.generate_code.fail"))
	}
	clientIp := core.GetClientIpFromRequest(request)
	cacheKey := fmt.Sprintf("USER_LOGIN_RETRIES:%s", clientIp)
	mustValidateCode := cache.Has(cacheKey)
	loginRetries := 0
	if mustValidateCode {
		loginRetries = cache.Get(cacheKey).(int)
	}

	return core.Success(map[string]interface{}{
		"must_validate_code":   mustValidateCode,
		"login_retries":        loginRetries,
		"max_login_retries":    5,
		"validate_code_base64": imgBase64,
		"validate_code_id":     id,
	})
}

func (user *User) UpdateProfile(request *http.Request) core.Response {
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	params, err := core.GetParamsFromRequest(request)

	if err != nil {
		return core.Fail(err)
	}

	_, err = public.SqliteWithClose(func(conn *db.Sqlite) (interface{}, error) {
		userInfo, err := conn.NewQuery().
			Table("users").
			Where("id = ?", public.GetSqlParams(uid)).
			Field([]string{"salt"}).
			Find()

		if err != nil || userInfo == nil {
			return nil, errors.New(core.Lan("user.not_found"))
		}
		fields := map[string]interface{}{
			"username": nil,
			"password": nil,
		}
		for k := range params {
			if _, ok := fields[k]; !ok {
				delete(params, k)
				continue
			}
			if params[k].(string) == "" {
				delete(params, k)
				continue
			}
		}

		if _, ok := params["password"]; ok {
			if !public.IsComplexPassword(params["password"].(string)) {
				return nil, errors.New(core.Lan("user.pwd_complexity.fail"))
			}
			params["md5_passwd"], err = public.StringMd5WithSalt(params["password"].(string), userInfo["salt"].(string))
			if err != nil {
				return nil, errors.New(core.Lan("user.pwd_edit.fail"))
			}
			params["pwd_update_time"] = time.Now().Unix()
			delete(params, "password")
		}
		if len(params) == 0 {
			return core.Success(core.Lan("user.op.success")), nil
		}
		_, err = conn.NewQuery().
			Table("users").
			Where("id = ?", public.GetSqlParams(uid)).
			Update(params)

		if err != nil {
			return nil, errors.New(core.Lan("modules.replacement.op.fail"))
		}
		return core.Success(core.Lan("user.op.success")), nil
	})

	if err != nil {
		return core.Fail(err)
	}
	lst := make([]string, 0)
	if _, ok := params["username"]; ok {
		lst = append(lst, core.Lan("user.username"))
	}

	if _, ok := params["md5_passwd"]; ok {
		lst = append(lst, core.Lan("user.password"))
	}
	public.WriteOptLog(fmt.Sprintf(core.Lan("user.log.update"), strings.Join(lst, ", ")), public.OPT_LOG_TYPE_UPDATE_PROFILE_SUCCESS, uid)
	return core.Success(core.Lan("user.op.success"))
}

func (user *User) Profile(request *http.Request) core.Response {
	token, err := jwt.ParseTokenWithRequest(request)

	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()

	userinfo := struct {
		Id         int
		Username   string
		CreateTime int
	}{}
	err = public.S("users").
		Where("id = ?", public.GetSqlParams(uid)).
		Field([]string{"id", "username", "create_time"}).
		FindAs(&userinfo)

	if err != nil {
		return core.Fail(core.Lan("user.not_found"))
	}
	btAccountInfo := types.BtAccountInfo{}
	if public.FileExists(public.BT_USERINFO_FILE) {
		if bs, err := os.ReadFile(public.BT_USERINFO_FILE); err == nil {
			if err = json.Unmarshal(bs, &btAccountInfo); err == nil {
				btAccountInfo.Username = btAccountInfo.Username[:3] + "****" + btAccountInfo.Username[7:]
			}
		}
	}
	auth, _ := core.Auth()
	data, err := public.Rconfigfile(core.AbsPath("./config/sysconfig.json"))
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := data["title"]; !ok {
		data["title"] = core.Lan("user.waf_title")
	}
	_, err = os.Stat(core.AbsPath("./config/logo.txt"))
	if err != nil {
		file, err := os.Create(core.AbsPath("./config/logo.txt"))
		if err != nil {
			return core.Fail(err)
		}
		defer file.Close()
	}

	logo, err := public.ReadFile(core.AbsPath("./config/logo.txt"))
	if err != nil {
		return core.Fail(err)
	}

	maliciousIpShared := false
	if _, err = os.Stat(public.MALICIOUS_IP_SHARE_PLAIN_FLAG_FILE); err == nil {
		maliciousIpShared = true
	}

	return core.Success(map[string]interface{}{
		"create_time": userinfo.CreateTime,
		"id":          userinfo.Id,
		"username":    userinfo.Username,
		"admin_path":  public.AdminPath(),
		"uuid":        authorization.UUID(),
		"bt_account": map[string]interface{}{
			"phone": btAccountInfo.Username,
			"ip":    btAccountInfo.Ip,
		},
		"authInfo":            auth,
		"version":             core.GetServerVersion(),
		"title":               data["title"],
		"logo":                logo,
		"malicious_ip_shared": maliciousIpShared,
		"language":            core.Language(),
	})
}

func (user *User) Update(request *http.Request) core.Response {
	curVer := core.GetServerVersion()
	latestVer, err := public.LatestVersion()
	if err != nil {
		return core.Fail(err)
	}
	if !public.CompareVersion(curVer, latestVer.Version) {
		return core.Success(core.Lan("modules.user.latest_version"))
	}
	go func() {
		time.Sleep(10 * time.Millisecond)
		switch clusterCommon.ClusterState() {
		case clusterCommon.CLUSTER_DISABLED:
			if _, err := public.ExecCommandCombined("bash", "-c", "nohup cat /www/cloud_waf/console/data/.pid|xargs kill -9; bash /www/cloud_waf/btw.init 17 >> "+core.AbsPath("./logs/error.log")+" 2>&1 &"); err != nil {
				logging.Error(core.Lan("modules.user.update.fail"), err)
			}
		}
	}()

	_ = public.WriteOptLog("更新版本: "+curVer+" -> "+latestVer.Version, public.OPT_LOG_TYPE_USER_OPERATION, public.GetUid(request))
	return core.Success(fmt.Sprintf(core.Lan("modules.user.update.success"), latestVer.Version))
}

func (user *User) Repair(request *http.Request) core.Response {
	go func() {
		time.Sleep(10 * time.Millisecond)
		switch clusterCommon.ClusterState() {
		case clusterCommon.CLUSTER_DISABLED:
			if _, err := public.ExecCommandCombined("bash", "-c", "nohup cat /www/cloud_waf/console/data/.pid|xargs kill -9; bash /www/cloud_waf/btw.init 17 >> "+core.AbsPath("./logs/error.log")+" 2>&1 &"); err != nil {
				logging.Error(core.Lan("modules.user.repair.fail"), err)
			}
		}
	}()

	return core.Success(core.Lan("modules.user.repair.success"))
}

func (user *User) Restart(request *http.Request) core.Response {
	_, err := public.ExecCommandCombined("bash", "-c", "nohup /www/cloud_waf/console/CloudWaf >> /www/cloud_waf/console/logs/error.log 2>&1 &")

	if err != nil {
		return core.Fail(core.Lan("modules.user.restart.fail"))
	}

	return core.Success(core.Lan("modules.user.restart.success"))
}

func (user *User) CheckStatus(request *http.Request) core.Response {
	return core.Success(core.Lan("modules.user.restart.success"))
}

func (user *User) LatestVersion(request *http.Request) core.Response {
	latestVer, err := public.LatestVersion()
	if err != nil {
		return core.Fail(err)
	}

	return core.Success(map[string]any{
		"latest_version": latestVer.Version,
		"description":    latestVer.Description,
		"create_time":    latestVer.CreateTime,
		"cur_version":    core.GetServerVersion(),
	})
}

func (user *User) UpdateMaliciousIp(request *http.Request) core.Response {
	public.UpdateMaliciousIp()
	return core.Success(core.Lan("modules.user.update_malicious_ip.success"))
}

func (user *User) GetMaliciousIpSharePlainText(request *http.Request) core.Response {
	cacheKey := "MaliciousIpSharePlainText"
	if cache.Has(cacheKey) {
		return core.Success(cache.Get(cacheKey))
	}
	resAny, errAny := public.PanelRequest(public.URL_BT_GET_MALICIOUS_IP_SHARE_PLAIN_TEXT, map[string]any{})

	if errAny != nil {
		return core.Fail(errAny)
	}
	cache.Set(cacheKey, resAny, 86400)
	return core.Success(resAny)
}

func (user *User) ConfirmMaliciousIpSharePlain(request *http.Request) core.Response {
	params := struct {
		Confirm int `json:"confirm"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.user.get_param.fail"), err))
	}

	switch params.Confirm {
	case 0:
		if _, err := os.Stat(public.MALICIOUS_IP_SHARE_PLAIN_FLAG_FILE); err != nil {
			return core.Fail(core.Lan("modules.user.not_join_plan"))
		}

		if err := os.Remove(public.MALICIOUS_IP_SHARE_PLAIN_FLAG_FILE); err != nil {
			return core.Fail(core.Lan("modules.user.cancel_plan.fail"))
		}

		return core.Success(core.Lan("modules.user.cancel_plan.success"))
	case 1:
		if err := os.WriteFile(public.MALICIOUS_IP_SHARE_PLAIN_FLAG_FILE, []byte(""), 0644); err != nil {
			return core.Fail(core.Lan("modules.user.join_plan.fail"))
		}
		public.UpdateMaliciousIp()
		return core.Success(core.Lan("modules.user.join_plan.success"))
	}
	return core.Fail(core.Lan("modules.user.unknown.error"))
}

func (user *User) SubmitClaimText(request *http.Request) core.Response {
	params := struct {
		ClaimText string `json:"claim_text"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.user.param.error"), err))
	}

	if params.ClaimText == "" {
		return core.Fail(core.Lan("modules.user.claim_text.empty"))
	}

	userinfo := public.NewBtAccountInfo()

	public.PanelRequest(public.URL_BT_API+"/bt_waf/submit_claim_text", map[string]any{
		"uid":        userinfo.Uid,
		"server_id":  userinfo.ServerId,
		"claim_text": params.ClaimText,
		"x_bt_token": "ODYyMDBhYmM2Njc4ZjgwOGNmMWQ0Mzgy",
	})

	return core.Success(core.Lan("modules.user.submit.success"))
}

func (user *User) SubmitNginxError(request *http.Request) core.Response {
	public.SubmitNginxError()
	return core.Success(core.Lan("modules.user.submit.success"))
}
