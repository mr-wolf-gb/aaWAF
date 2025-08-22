package modules

import (
	"CloudWaf/core"
	"CloudWaf/core/authorization"
	"CloudWaf/core/cache"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/public/db"
	"CloudWaf/types"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func init() {
	core.RegisterModule(&Auth{})

}

type Auth struct{}

func (au *Auth) Info(request *http.Request) core.Response {
	auth, err := core.Auth()
	if err != nil {
		return core.Fail(err)
	}
	return core.Success(auth)
}

func (au *Auth) Update(request *http.Request) core.Response {
	auth, err := core.Auth()
	if err != nil {
		return core.Fail(err)
	}
	if err = auth.ParseLicense(); err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.auth.parse_local_auth_info.fail"), err))
	}
	if err = au.update(); err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.auth.refresh_auth_info.fail"), err))
	}
	return core.Success(core.Lan("modules.auth.op.success"))
}

func (au *Auth) update() error {
	auth, _ := core.Auth()
	res := struct {
		License   string `json:"license"`
		PublicKey string `json:"public_key"`
	}{}
	resAny, errAny := public.PanelRequest(public.URL_BT_AUTH+"/update_license", map[string]interface{}{
		"data": map[string]interface{}{
			"product": auth.Product,
		},
	})
	if errAny != nil {
		if err, ok := errAny.(error); ok {
			return err
		}
		return errors.New(core.Lan("modules.auth.comm_to_bt.fail"))
	}
	if err := public.MapToStruct(resAny, &res); err != nil {
		return err
	}
	licenseBytes := []byte(res.License)
	if _, err := authorization.ParseLicense(licenseBytes, res.PublicKey); err != nil {
		return err
	}
	if err := authorization.SaveLicenseFile(licenseBytes); err != nil {
		return err
	}
	return nil
}

func (au *Auth) Uuid(request *http.Request) core.Response {
	return core.Success(authorization.UUID())
}

func (au *Auth) MountLicense(request *http.Request) core.Response {
	err := request.ParseMultipartForm(10 << 10)
	if err != nil {
		return core.Fail(core.Lan("modules.auth.upload_auth_file.fail.size"))
	}
	f, fh, err := request.FormFile("license")
	if err != nil {
		return core.Fail(core.Lan("modules.auth.upload_auth_file.fail") + err.Error())
	}
	defer f.Close()
	if !strings.HasSuffix(fh.Filename, ".license") {
		return core.Fail(core.Lan("modules.auth.upload_auth_file.fail.invalid_1"))
	}
	bs, err := io.ReadAll(f)
	if err != nil {
		return core.Fail(core.Lan("modules.auth.upload_auth_file.fail.invalid_2"))
	}
	auth, err := authorization.ParseLicense(bs, "")
	if err != nil {
		return core.Fail(core.Lan("modules.auth.upload_auth_file.fail.invalid_3"))
	}
	if err = auth.Validate(); err != nil {
		return core.Fail(core.Lan("modules.auth.upload_auth_file.fail") + err.Error())
	}
	if err = authorization.SaveLicenseFile(bs); err != nil {
		return core.Fail(core.Lan("modules.auth.upload_auth_file.fail") + err.Error())
	}
	return core.Success(core.Lan("modules.auth.set_auth_file.success"))
}

func (au *Auth) Login(request *http.Request) core.Response {
	params := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	_, errAny := public.PanelRequest(public.URL_BT_AUTH+"/login", map[string]interface{}{
		"data": map[string]interface{}{
			"username": params.Username,
			"password": params.Password,
		},
	})
	if errAny != nil {
		return core.Fail(errAny)
	}
	if err := au.update(); err != nil {
		logging.Error(core.Lan("modules.auth.recover_auth.fail"), err)
	}
	return core.Success(core.Lan("modules.auth.bind.success"))
}

func (au *Auth) Logout(request *http.Request) core.Response {
	if !public.FileExists(public.BT_USERINFO_FILE) {
		return core.Success(core.Lan("modules.auth.unbind.success"))
	}
	if err := os.Remove(public.BT_USERINFO_FILE); err != nil {
		return core.Fail(core.Lan("modules.auth.unbind.fail") + err.Error())
	}
	auth, _ := core.Auth()
	auth.Reset()
	_ = authorization.UnsetLicenseFile()

	return core.Success(core.Lan("modules.auth.unbind.success"))
}

func (au *Auth) Userinfo(request *http.Request) core.Response {
	if !public.FileExists(public.BT_USERINFO_FILE) {
		return core.Fail(core.Lan("modules.auth.not_bind_bt_account"))
	}
	bs, err := os.ReadFile(public.BT_USERINFO_FILE)
	if err != nil {
		return core.Fail(core.Lan("modules.auth.get_bt_account_info.fail") + err.Error())
	}
	userinfo := types.BtAccountInfo{}

	if err = json.Unmarshal(bs, &userinfo); err != nil {
		return core.Fail(core.Lan("modules.auth.get_bt_account_info.fail") + err.Error())
	}
	return core.Success(map[string]interface{}{
		"phone": userinfo.Username[:3] + "****" + userinfo.Username[7:],
		"ip":    userinfo.Ip,
	})
}

func (au *Auth) Pricing(request *http.Request) core.Response {
	res, errAny := public.PanelRequest(public.URL_BT_BRANDNEW+"/common_v2_authorization/get_pricing", map[string]interface{}{
		"product": public.P_NAME,
	})
	if errAny != nil {
		return core.Fail(errAny)
	}
	return core.Success(res)
}

func (au *Auth) CreateOrder(request *http.Request) core.Response {
	params := struct {
		ProductId int `json:"product_id"`
		Cycle     int `json:"cycle"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.ProductId == 0 {
		return core.Fail(core.Lan("modules.auth.product_id.missing"))
	}
	if params.Cycle == 0 {
		return core.Fail(core.Lan("modules.auth.auth_period.missing"))
	}
	res, errAny := public.PanelRequest(public.URL_BT_BRANDNEW+"/common_v2_authorization/create_order", map[string]interface{}{
		"src":        2,
		"product_id": params.ProductId,
		"cycle":      params.Cycle,
	})
	if errAny != nil {
		return core.Fail(errAny)
	}
	return core.Success(res)
}

func (au *Auth) OrderStatus(request *http.Request) core.Response {
	params := struct {
		OutTradeNo string `json:"out_trade_no"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}

	if len(params.OutTradeNo) != 15 {
		return core.Fail(core.Lan("modules.auth.order_no.invalid"))
	}
	res, errAny := public.PanelRequest(public.URL_BT_BRANDNEW+"/order/product/detect", map[string]interface{}{
		"out_trade_no": params.OutTradeNo,
	})
	if errAny != nil {
		return core.Fail(errAny)
	}
	orderStatus := struct {
		Status int `json:"status"`
	}{}
	if err := public.MapToStruct(res, &orderStatus); err != nil {
		return core.Fail(err)
	}
	if orderStatus.Status == 1 {
		if _, err := core.Auth(); err != nil {
			if err := au.activateLicenseWithOutTradeNo(params.OutTradeNo); err != nil {
				logging.Info(core.Lan("modules.auth.activate_auth.fail"), err)
			}
		}
	}
	return core.Success(res)
}

func (au *Auth) UnactivatedLicenses(request *http.Request) core.Response {
	res, errAny := public.PanelRequest(public.URL_BT_AUTH+"/get_unactivated_licenses", map[string]interface{}{
		"data": map[string]interface{}{
			"product": public.P_NAME,
		},
	})
	if errAny != nil {
		return core.Fail(errAny)
	}
	type item1 struct {
		Id        string                 `json:"id"`
		AuthInfo  authorization.AuthInfo `json:"auth_info"`
		Durations int64                  `json:"durations"`
	}
	type item2 struct {
		Type     int     `json:"type"`
		Name     string  `json:"name"`
		Children []item1 `json:"_children"`
	}
	m := make(map[int][]item1)
	for _, v := range res.([]any) {
		t := item1{}
		if err := public.MapToStruct(v, &t); err != nil {
			continue
		}
		m[t.AuthInfo.Extra.Type] = append(m[t.AuthInfo.Extra.Type], t)
	}
	result := make([]item2, 0)
	nameMap := map[int]string{
		0: core.Lan("modules.auth.free_version"),
		1: core.Lan("modules.auth.pro_version"),
		2: core.Lan("modules.auth.flagship_version"),
		3: core.Lan("modules.auth.enterprise_version"),
	}
	for k, v := range m {
		result = append(result, item2{
			Type:     k,
			Name:     nameMap[k],
			Children: v,
		})
	}
	return core.Success(result)
}

func (au *Auth) ActivateLicense(request *http.Request) core.Response {
	params := struct {
		Id string `json:"id"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	res := struct {
		License   string `json:"license"`
		PublicKey string `json:"public_key"`
	}{}
	resAny, errAny := public.PanelRequest(public.URL_BT_AUTH+"/activate_license", map[string]interface{}{
		"data": map[string]interface{}{
			"id": params.Id,
		},
	})
	if errAny != nil {
		return core.Fail(errAny)
	}
	if err := public.MapToStruct(resAny, &res); err != nil {
		return core.Fail(err)
	}
	licenseBytes := []byte(res.License)
	if _, err := authorization.ParseLicense(licenseBytes, res.PublicKey); err != nil {
		return core.Fail(err)
	}
	if err := authorization.SaveLicenseFile(licenseBytes); err != nil {
		return core.Fail(err)
	}
	auth, err := core.Auth()
	if err != nil {
		return core.Fail(err)
	}
	auth.Reset()
	return core.Success(core.Lan("modules.auth.activate.success"))
}

func (au *Auth) activateLicenseWithOutTradeNo(outTradeNo string) error {

	res := struct {
		License   string `json:"license"`
		PublicKey string `json:"public_key"`
	}{}
	resAny, errAny := public.PanelRequest(public.URL_BT_AUTH+"/activate_license", map[string]interface{}{
		"data": map[string]interface{}{
			"out_trade_no": outTradeNo,
		},
	})
	if errAny != nil {
		if v, ok := errAny.(error); ok {
			return v
		}
		return errors.New(core.Lan("modules.auth.activate_with_order_no.fail"))
	}
	if err := public.MapToStruct(resAny, &res); err != nil {
		return err
	}
	licenseBytes := []byte(res.License)
	if _, err := authorization.ParseLicense(licenseBytes, res.PublicKey); err != nil {
		return err
	}
	if err := authorization.SaveLicenseFile(licenseBytes); err != nil {
		return err
	}
	auth, err := core.Auth()
	if err != nil {
		return err
	}
	auth.Reset()
	return nil
}

func (au *Auth) GetNpsQuestions(request *http.Request) core.Response {
	cacheKey := "AUTH__GetNpsQuestions"
	if cache.Has(cacheKey) {
		return core.Success(cache.Get(cacheKey))
	}
	res, errAny := public.PanelRequest(public.URL_BT_BRANDNEW+"/contact/nps/questions", map[string]interface{}{
		"product_type": public.NPS_TYPE,
	})
	if errAny != nil {
		return core.Fail(errAny)
	}
	cache.Set(cacheKey, res, 600)
	return core.Success(res)
}

func (au *Auth) SubmitNps(request *http.Request) core.Response {
	params := struct {
		Rate      int    `json:"rate"`
		Feedback  string `json:"feedback"`
		PhoneBack int    `json:"phone_back"`
		Questions string `json:"questions"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	cacheKey := "AUTH__SubmitNps"
	if cache.Has(cacheKey) {
		return core.Fail(core.Lan("modules.auth.questionnaire.frequent"))
	}
	_, errAny := public.PanelRequest(public.URL_BT_BRANDNEW+"/contact/nps/submit", map[string]interface{}{
		"product_type": public.NPS_TYPE,
		"rate":         params.Rate,
		"feedback":     params.Feedback,
		"phone_back":   params.PhoneBack,
		"questions":    html.UnescapeString(params.Questions),
	})
	if errAny != nil {
		return core.Fail(errAny)
	}
	cache.Set(cacheKey, nil, 600)
	return core.Success("ok")
}

func (au *Auth) CheckNpsSubmitted(request *http.Request) core.Response {
	cacheKey := "AUTH__CheckNpsSubmitted"
	if cache.Has(cacheKey) {
		return core.Success(cache.Get(cacheKey))
	}
	firstLoginTime, _ := public.SqliteWithClose(func(conn *db.Sqlite) (any, error) {
		uInfo := struct {
			FirstLoginTime int64 `json:"first_login_time"`
		}{}

		info, err := conn.NewQuery().
			Table("logs").
			Where("log_type = ?", []any{public.OPT_LOG_TYPE_LOGIN_SUCCESS}).
			Field([]string{"min(`create_time`) as `first_login_time`"}).
			Find()

		if err != nil || info == nil {
			return 0, nil
		}
		if err = core.MapToStruct(info, &uInfo); err != nil {
			return 0, err
		}
		return uInfo.FirstLoginTime, nil
	})
	_, err := public.PanelRequest(public.URL_BT_BRANDNEW+"/contact/nps/check", map[string]interface{}{
		"product_type": public.NPS_TYPE,
	})
	result := map[string]any{
		"submitted":      err == nil,
		"installed_days": (time.Now().Unix() - firstLoginTime.(int64)) / 86400,
	}
	cache.Set(cacheKey, result, 600)
	return core.Success(result)
}

func (au *Auth) ObtainTrial(request *http.Request) core.Response {
	cacheKey := "__AUTH__OBTAINED_TRIAL__"
	if cache.Has(cacheKey) && cache.Get(cacheKey).(int) == 1 {
		return core.Fail(core.Lan("modules.auth.apply.frequent"))
	}
	resAny, errAny := public.PanelRequest(public.URL_BT_AUTH+"/obtain_btw_trial", map[string]interface{}{})
	if errAny != nil {
		return core.Fail(errAny)
	}
	res := struct {
		License   string `json:"license"`
		PublicKey string `json:"public_key"`
	}{}
	if err := public.MapToStruct(resAny, &res); err != nil {
		return core.Fail(err)
	}
	licenseBytes := []byte(res.License)
	if _, err := authorization.ParseLicense(licenseBytes, res.PublicKey); err != nil {
		return core.Fail(err)
	}
	if err := authorization.SaveLicenseFile(licenseBytes); err != nil {
		return core.Fail(err)
	}
	auth, err := core.Auth()

	if err != nil {
		return core.Fail(err)
	}
	auth.Reset()
	cache.Set(cacheKey, 1, 86400)
	return core.Success(core.Lan("modules.auth.apply.success"))
}

func (au *Auth) IsObtainedTrial(request *http.Request) core.Response {
	cacheKey := "__AUTH__OBTAINED_TRIAL__"
	if cache.Has(cacheKey) {
		return core.Success(cache.Get(cacheKey))
	}
	resAny, errAny := public.PanelRequest(public.URL_BT_AUTH+"/is_obtained_btw_trial", map[string]interface{}{})
	if errAny != nil {
		return core.Success(0)
	}
	res := struct {
		IsObtained int `json:"is_obtained"`
	}{}

	if err := public.MapToStruct(resAny, &res); err != nil {
		return core.Fail(err)
	}
	cache.Set(cacheKey, res.IsObtained, 86400)
	return core.Success(res.IsObtained)
}
