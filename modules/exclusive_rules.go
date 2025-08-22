package modules

import (
	"CloudWaf/core"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/public/db"
	"CloudWaf/types"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

func init() {
	core.RegisterModule(&Exclusive{
		exclusive_path:        "./tmp/exclusive.json",
		exclusive_path_backup: "./tmp/excl_backup.json",
		exclusive_path_show:   "./tmp/excl_show.json",
		exclu_rules: map[string]string{
			"huadong": core.Lan("modules.exclusive_rules.huadong"),
			"js":      core.Lan("modules.exclusive_rules.js"),
			"renji":   core.Lan("modules.exclusive_rules.renji"),
		},
	})
}

type Exclusive struct {
	exclusive_path        string
	exclusive_path_backup string
	exclusive_path_show   string
	exclu_rules           map[string]string
}

func (e *Exclusive) AddRules(request *http.Request) core.Response {
	timestamp := time.Now().Unix()
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["rule_name"].(string); !ok {
		return core.Fail("auth_type parameter error")
	}
	if _, ok := params["site_name"].(string); !ok {
		return core.Fail("auth_type parameter error")
	}
	if _, ok := params["ps"].(string); !ok {
		params["ps"] = ""
	}

	excData := types.Exclusive{
		SiteName:  params["site_name"].(string),
		RuleName:  params["rule_name"].(string),
		Timestamp: timestamp,
		Status:    1,
		PS:        params["ps"].(string),
		Count:     0,
	}
	json_data, err := public.ReadFile(e.exclusive_path_show)
	if err != nil {
		excDataSlice := make([]types.Exclusive, 0)
		excDataSlice = append(excDataSlice, excData)
		if e.sliceToMapLua(excDataSlice) == false {
			return core.Fail(core.Lan("modules.exclusive_rules.write_config.fail"))
		}
		bs, _ := json.Marshal(excData)
		_, err = public.WriteFile(e.exclusive_path_show, "["+string(bs)+"]")
		if err != nil {
			return core.Fail(core.Lan("modules.exclusive_rules.write_rule.fail"))
		}
		return core.Success(core.Lan("modules.exclusive_rules.add.success"))
	}
	file_data := make([]types.Exclusive, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return core.Fail(err)
	}
	file_data = append(file_data, excData)
	sort.Slice(file_data, func(i, j int) bool {
		return file_data[i].Timestamp > file_data[j].Timestamp
	})
	rules_js, err := json.Marshal(file_data)
	if err != nil {
		return core.Fail(core.Lan("modules.exclusive_rules.write_rule.fail"))
	}
	if e.sliceToMapLua(file_data) == false {
		return core.Fail(core.Lan("modules.exclusive_rules.write_config.fail"))
	} else {
		logging.Info(core.Lan("modules.exclusive_rules.map_sync.success"))
	}
	_, err = public.WriteFile(e.exclusive_path_show, string(rules_js))
	if err != nil {
		return core.Fail(core.Lan("modules.exclusive_rules.write_rule.fail"))
	}
	return core.Success(core.Lan("modules.exclusive_rules.add.success"))
}

func (e *Exclusive) DelRules(request *http.Request) core.Response {

	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["index"].([]interface{}); !ok {
		return core.Fail("index parameter error")
	}
	index := public.InterfaceArray_To_IntArray(params["index"].([]interface{}))
	sort.Sort(sort.Reverse(sort.IntSlice(index)))
	json_data, err := public.ReadFile(e.exclusive_path_show)
	if err != nil {
		return core.Fail(err)
	}
	file_data := make([]types.Exclusive, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return core.Fail(err)
	}
	del_rules := make([]types.Exclusive, 0)
	for _, number := range index {
		if number >= 0 && number < len(file_data) {
			del_rules = append(del_rules, file_data[number])
			file_data = append(file_data[:number], file_data[number+1:]...)
		}
	}
	rules_js, err := json.Marshal(file_data)
	if err != nil {
		return core.Fail(core.Lan("modules.exclusive_rules.write_config.fail"))
	}
	_, err = public.WriteFile(e.exclusive_path_show, string(rules_js))
	if err != nil {
		return core.Fail(core.Lan("modules.exclusive_rules.write_config.fail"))
	}

	return core.Success(core.Lan("modules.exclusive_rules.delete.success"))

}

func (e *Exclusive) GetList(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	json_data, err := public.ReadFile(e.exclusive_path_show)
	if err != nil {
		json_data = string("[]")
	}
	file_data := make([]interface{}, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return core.Fail(err)
	}
	if search, ok := params["keyword"].(string); ok && search != "" {
		file_data = e.searchItems(file_data, params["keyword"].(string))
	}
	var p int
	var p_size int
	if c, ok := params["p"]; ok {
		if v, ok := c.(float64); ok {
			p = int(v)
		} else {
			return core.Fail("p parameter error")
		}
	}
	if c, ok := params["p_size"]; ok {
		if v, ok := c.(float64); ok {
			p_size = int(v)
		} else {
			return core.Fail("p_size parameter error")
		}
	}
	data2 := public.PaginateData(file_data, p, p_size)
	return core.Success(data2)

}

func (e *Exclusive) RuleStatus(request *http.Request) core.Response {
	var log string
	timestamp := time.Now().Unix()
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["index"].(float64); !ok {
		return core.Fail("index parameter error")
	}
	index := params["index"].(float64)
	json_data, err := public.ReadFile(e.exclusive_path_show)
	if err != nil {
		return core.Fail(err)
	}
	file_data := make([]types.Exclusive, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return core.Fail(err)
	}
	if v, ok := params["status"]; ok {
		if c, ok := v.(float64); ok {
			if file_data[int(index)].Status != c {
				if c == 0 {
					log = core.Lan("modules.exclusive_rules.disable_rule")
				} else {
					log = core.Lan("modules.exclusive_rules.enable_rule")
				}
			}
			file_data[int(index)].Status = c
			file_data[int(index)].Timestamp = timestamp
		}
	}

	rules_js, err := json.Marshal(file_data)
	if err != nil {
		logging.Error(core.Lan("modules.exclusive_rules.json_transform.fail"), err)
	}
	_, err = public.WriteFile(e.exclusive_path_show, string(rules_js))
	if err != nil {
		return core.Fail(core.Lan("modules.exclusive_rules.write_config.fail"))
	}
	fmt.Printf("log: %s", log)
	return core.Success(core.Lan("modules.exclusive_rules.edit.success"))

}

func (e *Exclusive) ClearCount(request *http.Request) core.Response {

	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["index"].(float64); !ok {
		return core.Fail("index parameter error")
	}
	index := params["index"].(float64)
	json_data, err := public.ReadFile(e.exclusive_path_show)
	if err != nil {
		return core.Fail(err)
	}

	file_data := make([]types.Exclusive, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return core.Fail(err)
	}
	file_data[int(index)].Count = 0
	rules_js, err := json.Marshal(file_data)
	if err != nil {
		logging.Error(core.Lan("modules.exclusive_rules.json_transform.fail"), err)
	}
	_, err = public.WriteFile(e.exclusive_path_show, string(rules_js))
	if err != nil {
		return core.Fail(core.Lan("modules.exclusive_rules.write_config.fail"))
	}
	return core.Success(core.Lan("modules.exclusive_rules.clear.success"))

}

func (e *Exclusive) UpdateRules(request *http.Request) core.Response {

	timestamp := time.Now().Unix()
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["index"].(float64); !ok {
		return core.Fail("index parameter error")
	}
	if _, ok := params["rule_name"].(string); !ok {
		return core.Fail("auth_type parameter error")
	}
	if _, ok := params["site_name"].(string); !ok {
		return core.Fail("auth_type parameter error")
	}
	if _, ok := params["ps"].(string); !ok {
		params["ps"] = ""
	}
	index := params["index"].(float64)
	json_data, err := public.ReadFile(e.exclusive_path_show)
	if err != nil {
		return core.Fail(err)
	}
	file_data := make([]types.Exclusive, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return core.Fail(err)
	}
	file_data[int(index)].Timestamp = timestamp
	file_data[int(index)].RuleName = params["rule_name"].(string)
	file_data[int(index)].SiteName = params["site_name"].(string)
	file_data[int(index)].PS = params["ps"].(string)
	sort.Slice(file_data, func(i, j int) bool {
		return file_data[i].Timestamp > file_data[j].Timestamp
	})

	rules_js, err := json.Marshal(file_data)
	if err != nil {
		return core.Fail(core.Lan("modules.exclusive_rules.write_config.fail"))
	}
	_, err = public.WriteFile(e.exclusive_path_show, string(rules_js))
	if err != nil {
		return core.Fail(core.Lan("modules.exclusive_rules.write_config.fail"))
	}

	return core.Success(core.Lan("modules.exclusive_rules.edit.success"))
}

func (e *Exclusive) searchItems(items []interface{}, keyword string) []interface{} {
	var results []interface{}

	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		siteName, siteNameOk := itemMap["site_name"].(string)
		ruleName, ruleNameOk := itemMap["rule_name"].(string)
		ps, psOk := itemMap["ps"].(string)

		if siteNameOk && strings.Contains(siteName, keyword) ||
			ruleNameOk && strings.Contains(ruleName, keyword) ||
			psOk && strings.Contains(ps, keyword) {
			results = append(results, item)
		}
	}

	return results
}

func (e *Exclusive) backspaceExcl() bool {
	json_data, err := public.ReadFile(e.exclusive_path_backup)
	if err != nil {
		return false
	}

	rules_js, err := json.Marshal(json_data)
	if err != nil {
		logging.Error(core.Lan("modules.exclusive_rules.json_transform.fail"), err)
	}

	_, err = public.WriteFile(e.exclusive_path, string(rules_js))
	if err != nil {
		logging.Error(core.Lan("modules.exclusive_rules.rollback.fail"), err)
		return false
	}
	return true
}

func (e *Exclusive) backupExcl() bool {
	json_data, err := public.ReadFile(e.exclusive_path)
	if err != nil {
		return true
	}
	_, err = public.WriteFile(e.exclusive_path_backup, string(json_data))
	if err != nil {
		return false
	}
	return true
}

func (e *Exclusive) sliceToMapLua(data []types.Exclusive) bool {
	if e.backupExcl() == false {
		logging.Error(core.Lan("modules.exclusive_rules.backup.fail"))
	} else {
		logging.Info(core.Lan("modules.exclusive_rules.backup.success"))
	}
	result := make(map[string]types.Exclusive)
	for _, item := range data {
		result[item.SiteName] = item
	}
	rules_js, err := json.Marshal(result)
	if err != nil {
		return false
	}
	if err != nil {
		return false
	}
	_, err = public.WriteFile(e.exclusive_path, string(rules_js))
	if err != nil {
		if e.backspaceExcl() == false {
			logging.Error(core.Lan("modules.exclusive_rules.rollback.fail"))
		} else {
			logging.Info(core.Lan("modules.exclusive_rules.rollback.success"))
		}
		return false
	}
	return true

}

func (e *Exclusive) updateBlockStatus(site_id float64, status float64) error {
	_, err := public.SqliteWithClose(func(conn *db.Sqlite) (interface{}, error) {
		query := conn.NewQuery()
		query.Table("bt_exclusive_config").
			Field([]string{"site_id", "status"})
		if site_id != 0 {
			query.Where("site_id = ?", public.GetSqlParams(site_id))
		}
		num, err := query.Update(map[string]interface{}{
			"status": status,
		})
		return num, err
	})
	return err
}
