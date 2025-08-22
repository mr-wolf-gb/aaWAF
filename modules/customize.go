package modules

import (
	"CloudWaf/core"
	"CloudWaf/core/common"
	"CloudWaf/core/language"
	"CloudWaf/public"
	"CloudWaf/public/db"
	"CloudWaf/types"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

func init() {
	operatorMap := map[string]string{
		"regexp": "regexp",
		"^=":     "prefix",
		"$=":     "suffix",
		"%=":     "like",
		"=":      "eq",
		"!=":     "neq",
		"<>":     "neq",
		"in":     "in",
		"not in": "not_in",
		">":      "gt",
		">=":     "egt",
		"<":      "lt",
		"<=":     "elt",
	}
	operators := make([]string, 0)
	for k := range operatorMap {
		operators = append(operators, regexp.QuoteMeta(k))
	}
	core.RegisterModule(&Customize{
		operatorMap:    operatorMap,
		logicOrRegexp:  regexp.MustCompile(`(?i)\s+or\s+`),
		logicAndRegexp: regexp.MustCompile(`(?i)\s+and\s+`),
		exprReg:        regexp.MustCompile(`(?i)^([\s\S]+?)(` + strings.Join(operators, "|") + `)([\s\S]+)$`),
	})
}

type Customize struct {
	mutex          sync.Mutex
	operatorMap    map[string]string
	logicOrRegexp  *regexp.Regexp
	logicAndRegexp *regexp.Regexp
	exprReg        *regexp.Regexp
}

func (c *Customize) Create(request *http.Request) core.Response {
	entry := types.Entry{}
	if err := core.GetParamsFromRequestToStruct(request, &entry); err != nil {
		return core.Fail(err)
	}
	if err := entry.Validate(); err != nil {
		return core.Fail(err)
	}
	if entry.Src == 3 {
		if !public.IsUrl(entry.Action.Response.Body) {
			return core.Fail(core.Lan("modules.customize.url.incorrect"))
		}
	}
	rawData, err := entry.ToEntryFromDatabase()
	if err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.customize.create_rule.fail"), err))
	}
	rawData.CreateTime = time.Now().Unix()
	insertData := public.StructToMap(rawData)
	delete(insertData, "id")
	_, err = public.SqliteWithClose(func(conn *db.Sqlite) (res any, err error) {
		conn.Begin()
		defer func() {
			if err != nil {
				conn.Rollback()
				return
			}
			conn.Commit()
		}()
		id, err := conn.NewQuery().Table("customize_rules").Insert(insertData)
		if err != nil {
			return nil, err
		}
		if rawData.IsGlobal == 0 && len(entry.Servers) > 0 {
			insertAll := make([]types.WebsiteRuleLink, 0)
			for _, v := range entry.Servers {
				insertAll = append(insertAll, types.WebsiteRuleLink{
					RuleId:     int(id),
					ServerName: v,
				})
			}
			_, err = conn.NewQuery().Table("customize_rule_website").InsertAll(common.SliceToSliceMap(insertAll), db.EXTRA_IGNORE)

			if err != nil {
				return nil, err
			}
		}

		return nil, nil
	})
	if err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.customize.create_rule.db.fail"), err))
	}
	if err := c.syncConfigFile(); err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.customize.create_rule.sync.fail"), err))
	}
	return core.Success(core.Lan("modules.customize.create.success"))
}

func (c *Customize) ParseExpression(request *http.Request) core.Response {
	params := struct {
		Expr string `json:"expr"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.Expr == "" {
		return core.Fail(core.Lan("modules.customize.expr.empty"))
	}
	params.Expr = html.UnescapeString(params.Expr)
	return core.Success(c.parseExpression(params.Expr))
}

func (c *Customize) Update(request *http.Request) core.Response {
	entry := types.Entry{}
	if err := core.GetParamsFromRequestToStruct(request, &entry); err != nil {
		return core.Fail(err)
	}
	if entry.Id == 0 {
		return core.Fail(core.Lan("modules.customize.rule_id.empty"))
	}
	if !public.S("customize_rules").Where("id = ?", []any{entry.Id}).Exists() {
		return core.Fail(core.Lan("modules.customize.rule.not_found"))
	}
	if entry.Src == 3 {
		if !public.IsUrl(entry.Action.Response.Body) {
			return core.Fail(core.Lan("modules.customize.url.incorrect"))
		}
	}
	if err := entry.Validate(); err != nil {
		return core.Fail(err)
	}
	rawData, err := entry.ToEntryFromDatabase()
	if err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.customize.edit_rule.fail"), err))
	}
	_, err = public.SqliteWithClose(func(conn *db.Sqlite) (res any, err error) {
		conn.Begin()
		defer func() {
			if err != nil {
				conn.Rollback()
				return
			}
			conn.Commit()
		}()

		updateData := public.StructToMap(rawData)
		delete(updateData, "create_time")
		delete(updateData, "src")
		_, err = conn.NewQuery().Table("customize_rules").
			Where("id = ?", []any{rawData.Id}).
			Update(updateData)
		if err != nil {
			return nil, err
		}
		_, err = conn.NewQuery().
			Table("customize_rule_website").
			Where("rule_id = ?", []any{entry.Id}).
			Delete()
		if err != nil {
			return nil, err
		}
		if entry.IsGlobal == 0 && len(entry.Servers) > 0 {
			insertAll := make([]types.WebsiteRuleLink, 0)
			for _, v := range entry.Servers {
				insertAll = append(insertAll, types.WebsiteRuleLink{
					RuleId:     entry.Id,
					ServerName: v,
				})
			}
			_, err = conn.NewQuery().Table("customize_rule_website").InsertAll(common.SliceToSliceMap(insertAll), db.EXTRA_IGNORE)

			if err != nil {
				return nil, err
			}
		}
		if err != nil {
			return nil, err
		}
		return nil, nil
	})

	if err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.customize.edit_rule.db.fail"), err))
	}
	if err := c.syncConfigFile(); err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.customize.edit_rule.sync.fail"), err))
	}
	if entry.Src == 2 {
		idString := strconv.Itoa(entry.Id)
		public.HttpPostByToken("http://127.0.0.251/reset_customize_cc?rule_id="+idString, 2)
	}

	return core.Success(core.Lan("modules.customize.edit.success"))
}

func (c *Customize) Remove(request *http.Request) core.Response {
	params := struct {
		Ids []int `json:"ids"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if len(params.Ids) == 0 {
		return core.Fail(core.Lan("modules.customize.rule_id.empty"))
	}
	if !public.S("customize_rules").WhereIn("id", params.Ids).Exists() {
		return core.Fail(core.Lan("modules.customize.rule.not_found"))
	}
	_, err := public.SqliteWithClose(func(conn *db.Sqlite) (res any, err error) {
		conn.Begin()
		defer func() {
			if err != nil {
				conn.Rollback()
				return
			}
			conn.Commit()
		}()
		_, err = conn.NewQuery().Table("customize_rules").WhereIn("id", params.Ids).Delete()
		if err != nil {
			return nil, err
		}
		_, err = conn.NewQuery().Table("customize_rule_website").WhereIn("rule_id", params.Ids).Delete()
		if err != nil {
			return nil, err
		}
		return nil, nil
	})

	if err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.customize.delete_rule.db.fail"), err))
	}
	if err := c.syncConfigFile(); err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.customize.delete_rule.sync.fail"), err))
	}
	return core.Success(core.Lan("modules.customize.delete.success"))
}

func (c *Customize) List(request *http.Request) core.Response {
	params := struct {
		Keyword string `json:"keyword"`
		P       int    `json:"p"`
		PSize   int    `json:"p_size"`
		Types   int    `json:"type"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}

	query := public.S("customize_rules").
		Field([]string{"id", "is_global", "status", "priority", "create_time", "execute_phase", "name", "servers", "action", "root", "src"}).
		Order("priority", "desc").
		Order("create_time", "desc")
	if params.Keyword != "" {
		query.Where("name like ?", []any{"%" + params.Keyword + "%"})
	}
	if params.Types > 1 {
		query.Where("src = ?", []any{params.Types})
	} else {
		query.Where("src < ?", []any{2})
	}
	res, err := public.SimplePage(query, params)

	if err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.customize.list.fail"), err))
	}
	m := struct {
		Total int                       `json:"total"`
		List  []types.EntryFromDatabase `json:"list"`
	}{}

	if err = public.MapToStruct(res, &m); err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.customize.list.fail"), err))
	}
	type entryForDisplay struct {
		*types.Entry
		Hit int `json:"hit"`
	}
	lst := make([]entryForDisplay, 0)
	hitMap := make(map[string]int)
	if bs, err := os.ReadFile(public.CUSTOMIZE_RULE_HIT_FILE); err == nil {
		if err := json.Unmarshal(bs, &hitMap); err != nil {
			return core.Fail(fmt.Errorf(core.Lan("modules.customize.list.get_hit.fail"), err))
		}
	}
	for _, v := range m.List {
		entry, err := v.ToEntry()

		if err != nil {
			return core.Fail(fmt.Errorf(core.Lan("modules.customize.list.fail"), err))
		}
		lst = append(lst, entryForDisplay{
			Entry: entry,
			Hit:   hitMap[strconv.Itoa(v.Id)],
		})
	}
	return core.Success(map[string]any{
		"total": m.Total,
		"list":  lst,
	})
}

func (c *Customize) GetConfigHelp(request *http.Request) core.Response {
	if core.Language() == language.EN {
		return c.getConfigHelpEN(request)
	}

	return c.getConfigHelpCN(request)
}

func (c *Customize) getConfigHelpCN(request *http.Request) core.Response {
	params := struct {
		Types int `json:"type"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	sitemap := make(map[string]string)
	if domain, err := public.GetAllDomain(); err == nil {
		for _, v := range domain {
			name, ok := v["name"]

			if !ok {
				continue
			}

			d, ok := v["domain"]

			if !ok {
				continue
			}

			sitemap[name] = d
		}
	}
	ipGroupEntry := make([]map[string]any, 0)
	if bs, err := os.ReadFile("/www/cloud_waf/nginx/conf.d/waf/rule/ip_group.json"); err == nil {
		ipGroup := make(map[string][]types.Group)
		if err := json.Unmarshal(bs, &ipGroup); err == nil {
			for k := range ipGroup {
				ipGroupEntry = append(ipGroupEntry, map[string]any{
					"key":   k,
					"label": k,
				})
			}
		}
	}
	ipGroupEntry = append(ipGroupEntry, map[string]any{
		"key":   "malicious_ip",
		"label": core.Lan("modules.customize.bt_malicious_ip_lib"),
	})

	if params.Types == 2 {
		return core.Success(map[string]any{
			"action": []map[string]any{
				{
					"type":         "deny",
					"text":         core.Lan("modules.customize.intercept"),
					"has_response": true,
					"cc":           map[string]any{"interval": 60, "threshold": 120},
					"block_time":   300,
					"response": []map[string]any{
						{
							"type": "black_page",
							"text": core.Lan("modules.customize.default_intercept_page"),
						},
						{
							"type": "no_response",
							"text": core.Lan("modules.customize.resp_444"),
						},
					},
				},
				{
					"type":         "validate",
					"text":         core.Lan("modules.customize.man_machine_ver"),
					"has_response": true,
					"response": []map[string]any{
						{
							"type": "validate_silence",
							"text": core.Lan("modules.customize.no_sense_ver"),
						},
						{
							"type": "validate_waiting",
							"text": core.Lan("modules.customize.wait_5s_ver"),
						},
						{
							"type": "validate_slide",
							"text": core.Lan("modules.customize.slide_ver"),
						},
					},
				},
			},
			"options": []map[string]any{
				{
					"type":                 "ip",
					"text":                 core.Lan("modules.customize.client_ip"),
					"operators":            []string{"eq", "neq"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.client_ip.placeholder"),
						"hint":        core.Lan("modules.customize.client_ip.hint"),
					},
				},
				{
					"type":                 "ip_group",
					"text":                 core.Lan("modules.customize.ip_group"),
					"operators":            []string{"in", "not_in"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          nil,
					"right_widget": map[string]any{
						"type":        "select",
						"value":       ipGroupEntry,
						"placeholder": core.Lan("modules.customize.ip_group.placeholder"),
						"hint":        "",
					},
				},
				{
					"type":                 "uri",
					"text":                 core.Lan("modules.customize.uri_no_param"),
					"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp", "in", "not_in"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.uri.placeholder"),
						"hint":        core.Lan("modules.customize.uri.hint"),
					},
				},
				{
					"type":                 "uri_with_param",
					"text":                 core.Lan("modules.customize.uri_with_param"),
					"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp", "in", "not_in"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.uri.placeholder"),
						"hint":        core.Lan("modules.customize.uri_with_param.hint"),
					},
				},
				{
					"type":                 "param",
					"text":                 core.Lan("modules.customize.uri_param"),
					"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp"},
					"left_factor_enabled":  true,
					"right_factor_enabled": true,
					"left_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.param_name.placeholder"),
						"hint":        core.Lan("modules.customize.param_name.hint"),
					},
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.param_value.placeholder"),
						"hint":        core.Lan("modules.customize.param_value.hint"),
					},
				},
			},
			"operators": map[string]map[string]any{
				"regexp": {
					"text":      core.Lan("modules.customize.regexp"),
					"data_type": "string",
				},
				"prefix": {
					"text":      core.Lan("modules.customize.match_start"),
					"data_type": "string",
				},
				"suffix": {
					"text":      core.Lan("modules.customize.match_end"),
					"data_type": "string",
				},
				"like": {
					"text":      core.Lan("modules.customize.like"),
					"data_type": "string",
				},
				"eq": {
					"text":      core.Lan("modules.customize.eq"),
					"data_type": "string",
				},
				"neq": {
					"text":      core.Lan("modules.customize.neq"),
					"data_type": "string",
				},
				"in": {
					"text":      core.Lan("modules.customize.in"),
					"data_type": "set",
				},
				"not_in": {
					"text":      core.Lan("modules.customize.not_in"),
					"data_type": "set",
				},
				"gt": {
					"text":      core.Lan("modules.customize.gt"),
					"data_type": "number",
				},
				"egt": {
					"text":      core.Lan("modules.customize.egt"),
					"data_type": "number",
				},
				"lt": {
					"text":      core.Lan("modules.customize.lt"),
					"data_type": "number",
				},
				"elt": {
					"text":      core.Lan("modules.customize.elt"),
					"data_type": "number",
				},
			},
			"sitemap":     sitemap,
			"status_code": []string{"444"},
		})
	}
	if params.Types == 3 {
		return core.Success(map[string]any{
			"action": []map[string]any{
				{
					"type":         "redirect",
					"text":         core.Lan("modules.customize.url_redirect"),
					"has_response": true,
					"response": []map[string]any{
						{
							"type": "301",
							"text": core.Lan("modules.customize.permanent_redirect"),
						},
						{
							"type": "302",
							"text": core.Lan("modules.customize.temporary_redirect"),
						},
					},
				},
			},
			"options": []map[string]any{
				{
					"type":                 "ip",
					"text":                 core.Lan("modules.customize.client_ip"),
					"operators":            []string{"eq", "neq"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.client_ip.placeholder"),
						"hint":        core.Lan("modules.customize.client_ip.hint"),
					},
				},
				{
					"type":                 "ip_range",
					"text":                 core.Lan("modules.customize.ip_range"),
					"operators":            []string{"in", "not_in"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.cidr.placeholder"),
						"hint":        core.Lan("modules.customize.cidr.hint"),
					},
				},
				{
					"type":                 "ip_group",
					"text":                 core.Lan("modules.customize.ip_group"),
					"operators":            []string{"in", "not_in"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          nil,
					"right_widget": map[string]any{
						"type":        "select",
						"value":       ipGroupEntry,
						"placeholder": core.Lan("modules.customize.ip_group.placeholder"),
						"hint":        "",
					},
				},
				{
					"type":                 "method",
					"text":                 core.Lan("modules.customize.req_method"),
					"operators":            []string{"eq", "neq", "in", "not_in"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type": "select",
						"value": []map[string]any{
							{
								"key":   "GET",
								"label": "GET",
							},
							{
								"key":   "POST",
								"label": "POST",
							},
							{
								"key":   "PUT",
								"label": "PUT",
							},
							{
								"key":   "DELETE",
								"label": "DELETE",
							},
							{
								"key":   "PATCH",
								"label": "PATCH",
							},
							{
								"key":   "TRACE",
								"label": "TRACE",
							},
							{
								"key":   "HEAD",
								"label": "HEAD",
							},
							{
								"key":   "OPTIONS",
								"label": "OPTIONS",
							},
							{
								"key":   "CONNECT",
								"label": "CONNECT",
							},
						},
						"placeholder": core.Lan("modules.customize.req_method.placeholder"),
						"hint":        "",
					},
				},
				{
					"type":                 "uri",
					"text":                 core.Lan("modules.customize.uri_no_param"),
					"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp", "in", "not_in"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.uri.placeholder"),
						"hint":        core.Lan("modules.customize.uri.hint"),
					},
				},
				{
					"type":                 "uri_with_param",
					"text":                 core.Lan("modules.customize.uri_with_param"),
					"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp", "in", "not_in"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.uri.placeholder"),
						"hint":        core.Lan("modules.customize.uri_with_param.hint"),
					},
				},
				{
					"type":                 "param_name",
					"text":                 core.Lan("modules.customize.uri_param_name"),
					"operators":            []string{"in", "not_in"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.param_name.placeholder"),
						"hint":        core.Lan("modules.customize.param_name.hint"),
					},
				},
				{
					"type":                 "param",
					"text":                 core.Lan("modules.customize.uri_req_param"),
					"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp"},
					"left_factor_enabled":  true,
					"right_factor_enabled": true,
					"left_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.param_name.placeholder"),
						"hint":        core.Lan("modules.customize.param_name.hint"),
					},
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.param_value.placeholder"),
						"hint":        "示例：xiaoming",
					},
				},
				{
					"type":                 "post_param",
					"text":                 core.Lan("modules.customize.post_req_param"),
					"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp"}, // 可用的运算符
					"left_factor_enabled":  true,                                                        // 是否启用左运算数
					"right_factor_enabled": true,                                                        // 是否启用右运算数
					"left_widget": map[string]any{
						"type":        "text",    // 组件类型
						"value":       "",        // 可选值
						"placeholder": core.Lan("modules.customize.param_name.placeholder"), // 默认占位文本
						"hint":        core.Lan("modules.customize.param_name.hint"),
					}, // 组件1
					"right_widget": map[string]any{
						"type":        "text",   // 组件类型
						"value":       "",       // 可选值
						"placeholder": core.Lan("modules.customize.param_value.placeholder"), // 默认占位文本
						"hint":        "示例：xiaoming",
					}, // 组件2
				},
				{
					"type":                 "body_param",
					"text":                 core.Lan("modules.customize.post_body_match"),
					"operators":            []string{"regexp", "eq", "neq", "prefix", "suffix", "like", "in", "not_in"}, // 可用的运算符
					"left_factor_enabled":  false,                                                                       // 是否启用左运算数
					"right_factor_enabled": true,                                                                        // 是否启用右运算数
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "text",      // 组件类型
						"value":       "",          // 可选值
						"placeholder": core.Lan("modules.customize.match_content.placeholder"), // 默认占位文本
						"hint":        core.Lan("modules.customize.match_content.hint"),
					}, // 组件
				},
				{
					"type":                 "request_header",
					"text":                 core.Lan("modules.customize.req_header"),
					"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp"},
					"left_factor_enabled":  true,
					"right_factor_enabled": true,
					"left_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.req_header_name.placeholder"),
						"hint":        core.Lan("modules.customize.req_header_name.hint"),
					},
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.match_value.placeholder"),
						"hint":        core.Lan("modules.customize.match_value.hint"),
					},
				},
				{
					"type":                 "user-agent",
					"text":                 "User Agent",
					"operators":            []string{"eq", "neq", "like"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.match_value.placeholder"),
						"hint":        core.Lan("modules.customize.user_agent.hint"),
					},
				},
				{
					"type":                 "referer",
					"text":                 core.Lan("modules.customize.referer"),
					"operators":            []string{"eq", "neq", "in", "not_in", "prefix", "suffix", "regexp"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.match_value.placeholder"),
						"hint":        core.Lan("modules.customize.referer.hint"),
					},
				},
				{
					"type":                 "request_header_name",
					"text":                 core.Lan("modules.customize.req_header_name"),
					"operators":            []string{"in", "not_in"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": core.Lan("modules.customize.req_header_name.placeholder"),
						"hint":        core.Lan("modules.customize.req_header_name.hint"),
					},
				},
			},
			"operators": map[string]map[string]any{
				"regexp": {
					"text":      core.Lan("modules.customize.regexp"),
					"data_type": "string",
				},
				"prefix": {
					"text":      core.Lan("modules.customize.match_start"),
					"data_type": "string",
				},
				"suffix": {
					"text":      core.Lan("modules.customize.match_end"),
					"data_type": "string",
				},
				"like": {
					"text":      core.Lan("modules.customize.like"),
					"data_type": "string",
				},
				"eq": {
					"text":      core.Lan("modules.customize.eq"),
					"data_type": "string",
				},
				"neq": {
					"text":      core.Lan("modules.customize.neq"),
					"data_type": "string",
				},
				"in": {
					"text":      core.Lan("modules.customize.in"),
					"data_type": "set",
				},
				"not_in": {
					"text":      core.Lan("modules.customize.not_in"),
					"data_type": "set",
				},
				"gt": {
					"text":      core.Lan("modules.customize.gt"),
					"data_type": "number",
				},
				"egt": {
					"text":      core.Lan("modules.customize.egt"),
					"data_type": "number",
				},
				"lt": {
					"text":      core.Lan("modules.customize.lt"),
					"data_type": "number",
				},
				"elt": {
					"text":      core.Lan("modules.customize.elt"),
					"data_type": "number",
				},
			},
			"sitemap": sitemap,
		})
	}

	return core.Success(map[string]any{
		"action": []map[string]any{
			{
				"type":         "allow",
				"text":         core.Lan("modules.customize.allow"),
				"has_response": false,
				"response":     make([]map[string]any, 0),
			},
			{
				"type":         "deny",
				"text":         core.Lan("modules.customize.intercept"),
				"has_response": true,
				"response": []map[string]any{
					{
						"type": "black_page",
						"text": core.Lan("modules.customize.default_intercept_page"),
					},
					{
						"type": "no_response",
						"text": core.Lan("modules.customize.resp_444"),
					},
				},
			},
			{
				"type":         "validate",
				"text":         core.Lan("modules.customize.man_machine_ver"),
				"has_response": true,
				"response": []map[string]any{
					{
						"type": "validate_silence",
						"text": core.Lan("modules.customize.no_sense_ver"),
					},
					{
						"type": "validate_waiting",
						"text": core.Lan("modules.customize.wait_5s_ver"),
					},
					{
						"type": "validate_slide",
						"text": core.Lan("modules.customize.slide_ver"),
					},
				},
			},
			{
				"type":         "record",
				"text":         core.Lan("modules.customize.record_only"),
				"has_response": false,
				"response":     make([]map[string]any, 0),
			},
		},
		"options": []map[string]any{
			{
				"type":                 "ip",
				"text":                 core.Lan("modules.customize.client_ip"),
				"operators":            []string{"eq", "neq"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": core.Lan("modules.customize.client_ip.placeholder"),
					"hint":        core.Lan("modules.customize.client_ip.hint"),
				},
			},
			{
				"type":                 "ip_range",
				"text":                 core.Lan("modules.customize.ip_range"),
				"operators":            []string{"in", "not_in"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": core.Lan("modules.customize.cidr.placeholder"),
					"hint":        core.Lan("modules.customize.cidr.hint"),
				},
			},
			{
				"type":                 "ip_group",
				"text":                 core.Lan("modules.customize.ip_group"),
				"operators":            []string{"in", "not_in"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          nil,
				"right_widget": map[string]any{
					"type":        "select",
					"value":       ipGroupEntry,
					"placeholder": core.Lan("modules.customize.ip_group.placeholder"),
					"hint":        "",
				},
			},
			{
				"type":                 "method",
				"text":                 core.Lan("modules.customize.req_method"),
				"operators":            []string{"eq", "neq", "in", "not_in"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type": "select",
					"value": []map[string]any{
						{
							"key":   "GET",
							"label": "GET",
						},
						{
							"key":   "POST",
							"label": "POST",
						},
						{
							"key":   "PUT",
							"label": "PUT",
						},
						{
							"key":   "DELETE",
							"label": "DELETE",
						},
						{
							"key":   "PATCH",
							"label": "PATCH",
						},
						{
							"key":   "TRACE",
							"label": "TRACE",
						},
						{
							"key":   "HEAD",
							"label": "HEAD",
						},
						{
							"key":   "OPTIONS",
							"label": "OPTIONS",
						},
						{
							"key":   "CONNECT",
							"label": "CONNECT",
						},
					},
					"placeholder": core.Lan("modules.customize.req_method.placeholder"),
					"hint":        "",
				},
			},
			{
				"type":                 "uri",
				"text":                 core.Lan("modules.customize.uri_no_param"),
				"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp", "in", "not_in"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": core.Lan("modules.customize.uri.placeholder"),
					"hint":        core.Lan("modules.customize.uri.hint"),
				},
			},
			{
				"type":                 "uri_with_param",
				"text":                 core.Lan("modules.customize.uri_with_param"),
				"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp", "in", "not_in"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": core.Lan("modules.customize.uri.placeholder"),
					"hint":        core.Lan("modules.customize.uri_with_param.hint"),
				},
			},
			{
				"type":                 "param_name",
				"text":                 core.Lan("modules.customize.uri_param_name"),
				"operators":            []string{"in", "not_in"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": core.Lan("modules.customize.param_name.placeholder"),
					"hint":        core.Lan("modules.customize.param_name.hint"),
				},
			},
			{
				"type":                 "param",
				"text":                 core.Lan("modules.customize.uri_req_param"),
				"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp"},
				"left_factor_enabled":  true,
				"right_factor_enabled": true,
				"left_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": core.Lan("modules.customize.param_name.placeholder"),
					"hint":        core.Lan("modules.customize.param_name.hint"),
				},
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": core.Lan("modules.customize.param_value.placeholder"),
					"hint":        "示例：xiaoming",
				},
			},
			{
				"type":                 "request_header",
				"text":                 core.Lan("modules.customize.req_header"),
				"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp"},
				"left_factor_enabled":  true,
				"right_factor_enabled": true,
				"left_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": core.Lan("modules.customize.req_header_name.placeholder"),
					"hint":        core.Lan("modules.customize.req_header_name.hint"),
				},
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": core.Lan("modules.customize.match_value.placeholder"),
					"hint":        core.Lan("modules.customize.match_value.hint"),
				},
			},
			{
				"type":                 "user-agent",
				"text":                 "User Agent",
				"operators":            []string{"eq", "neq", "like"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": core.Lan("modules.customize.match_value.placeholder"),
					"hint":        core.Lan("modules.customize.user_agent.hint"),
				},
			},
			{
				"type":                 "referer",
				"text":                 core.Lan("modules.customize.referer"),
				"operators":            []string{"eq", "neq", "in", "not_in", "prefix", "suffix", "regexp"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": core.Lan("modules.customize.match_value.placeholder"),
					"hint":        core.Lan("modules.customize.referer.hint"),
				},
			},
			{
				"type":                 "request_header_name",
				"text":                 core.Lan("modules.customize.req_header_name"),
				"operators":            []string{"in", "not_in"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": core.Lan("modules.customize.req_header_name.placeholder"),
					"hint":        core.Lan("modules.customize.req_header_name.hint"),
				},
			},
		},

		"operators": map[string]map[string]any{
			"regexp": {
				"text":      core.Lan("modules.customize.regexp"),
				"data_type": "string",
			},
			"prefix": {
				"text":      core.Lan("modules.customize.match_start"),
				"data_type": "string",
			},
			"suffix": {
				"text":      core.Lan("modules.customize.match_end"),
				"data_type": "string",
			},
			"like": {
				"text":      core.Lan("modules.customize.like"),
				"data_type": "string",
			},
			"eq": {
				"text":      core.Lan("modules.customize.eq"),
				"data_type": "string",
			},
			"neq": {
				"text":      core.Lan("modules.customize.neq"),
				"data_type": "string",
			},
			"in": {
				"text":      core.Lan("modules.customize.in"),
				"data_type": "set",
			},
			"not_in": {
				"text":      core.Lan("modules.customize.not_in"),
				"data_type": "set",
			},
			"gt": {
				"text":      core.Lan("modules.customize.gt"),
				"data_type": "number",
			},
			"egt": {
				"text":      core.Lan("modules.customize.egt"),
				"data_type": "number",
			},
			"lt": {
				"text":      core.Lan("modules.customize.lt"),
				"data_type": "number",
			},
			"elt": {
				"text":      core.Lan("modules.customize.elt"),
				"data_type": "number",
			},
		},
		"sitemap": sitemap,
	})
}

func (c *Customize) getConfigHelpEN(request *http.Request) core.Response {
	params := struct {
		Types int `json:"type"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	sitemap := make(map[string]string)
	if domain, err := public.GetAllDomain(); err == nil {
		for _, v := range domain {
			name, ok := v["name"]

			if !ok {
				continue
			}

			d, ok := v["domain"]

			if !ok {
				continue
			}

			sitemap[name] = d
		}
	}

	ipGroupEntry := make([]map[string]any, 0)
	if bs, err := os.ReadFile("/www/cloud_waf/nginx/conf.d/waf/rule/ip_group.json"); err == nil {
		ipGroup := make(map[string][]types.Group)
		if err := json.Unmarshal(bs, &ipGroup); err == nil {
			for k := range ipGroup {
				ipGroupEntry = append(ipGroupEntry, map[string]any{
					"key":   k,
					"label": k,
				})
			}
		}
	}
	ipGroupEntry = append(ipGroupEntry, map[string]any{
		"key":   "malicious_ip",
		"label": "Shared malicious IP library",
	})
	if params.Types == 2 {
		return core.Success(map[string]any{
			"action": []map[string]any{
				{
					"type":         "deny",
					"text":         "Block",
					"has_response": true,
					"cc":           map[string]any{"interval": 60, "threshold": 120},
					"block_time":   300,
					"response": []map[string]any{
						{
							"type": "black_page",
							"text": "Default blocking page",
						},
						{
							"type": "no_response",
							"text": "Response 444",
						},
					},
				},
			},
			"options": []map[string]any{
				{
					"type":                 "ip",
					"text":                 "Client IP",
					"operators":            []string{"eq", "neq"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": "Please enter client IP",
						"hint":        "e.g. 192.168.1.1",
					},
				},
				{
					"type":                 "ip_group",
					"text":                 "IP group",
					"operators":            []string{"in", "not_in"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          nil,
					"right_widget": map[string]any{
						"type":        "select",
						"value":       ipGroupEntry,
						"placeholder": "Please select an IP group",
						"hint":        "",
					},
				},
				{
					"type":                 "ip_belongs",
					"text":                 "IP location",
					"operators":            []string{"in", "not_in"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "area_select",
						"value":       "",
						"placeholder": "please select the region",
						"hint":        "",
					},
				},
				{
					"type":                 "uri",
					"text":                 "URI Path",
					"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp", "in", "not_in"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": "Please enter URI",
						"hint":        "e.g. /index.php",
					},
				},
				{
					"type":                 "uri_with_param",
					"text":                 "URI",
					"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp", "in", "not_in"},
					"left_factor_enabled":  false,
					"right_factor_enabled": true,
					"left_widget":          make(map[string]any),
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": "Please enter URI",
						"hint":        "e.g. /index.php?username=xiaoming",
					},
				},
				{
					"type":                 "param",
					"text":                 "URI Query string",
					"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp"},
					"left_factor_enabled":  true,
					"right_factor_enabled": true,
					"left_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": "Please enter parameter name",
						"hint":        "e.g. username",
					},
					"right_widget": map[string]any{
						"type":        "text",
						"value":       "",
						"placeholder": "Please enter parameter value",
						"hint":        "e.g. id=1",
					},
				},
			},
			"operators": map[string]map[string]any{
				"regexp": {
					"text":      "Regex",
					"data_type": "string",
				},
				"prefix": {
					"text":      "Prefix",
					"data_type": "string",
				},
				"suffix": {
					"text":      "Suffix",
					"data_type": "string",
				},
				"like": {
					"text":      "Like",
					"data_type": "string",
				},
				"eq": {
					"text":      "Equal",
					"data_type": "string",
				},
				"neq": {
					"text":      "Not equal",
					"data_type": "string",
				},
				"in": {
					"text":      "Incloud",
					"data_type": "set",
				},
				"not_in": {
					"text":      "Notincloud",
					"data_type": "set",
				},
				"gt": {
					"text":      "gt",
					"data_type": "number",
				},
				"egt": {
					"text":      "egt",
					"data_type": "number",
				},
				"lt": {
					"text":      "lt",
					"data_type": "number",
				},
				"elt": {
					"text":      "elt",
					"data_type": "number",
				},
			},

			"sitemap":     sitemap,
			"status_code": []string{"444"},
		})
	}

	return core.Success(map[string]any{
		"action": []map[string]any{
			{
				"type":         "allow",
				"text":         "Allow",
				"has_response": false,
				"response":     make([]map[string]any, 0),
			},
			{
				"type":         "deny",
				"text":         "Block",
				"has_response": true,
				"response": []map[string]any{
					{
						"type": "black_page",
						"text": "Default block page",
					},
					{
						"type": "no_response",
						"text": "Response 444",
					},
				},
			},
			{
				"type":         "validate",
				"text":         "Captcha",
				"has_response": true,
				"response": []map[string]any{
					{
						"type": "validate_silence",
						"text": "Silence",
					},
					{
						"type": "validate_waiting",
						"text": "Wait 5s",
					},
					{
						"type": "validate_slide",
						"text": "Swipe",
					},
				},
			},
			{
				"type":         "record",
				"text":         "Record only",
				"has_response": false,
				"response":     make([]map[string]any, 0),
			},
		},
		"options": []map[string]any{
			{
				"type":                 "ip",
				"text":                 "Client IP",
				"operators":            []string{"eq", "neq"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": "Please enter client IP",
					"hint":        "e.g. 192.168.1.1",
				},
			},
			{
				"type":                 "ip_range",
				"text":                 "IP range",
				"operators":            []string{"in", "not_in"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": "Please enter a CIDR expression",
					"hint":        "e.g. 192.168.1.0/24",
				},
			},
			{
				"type":                 "ip_group",
				"text":                 "IP Group",
				"operators":            []string{"in", "not_in"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          nil,
				"right_widget": map[string]any{
					"type":        "select",
					"value":       ipGroupEntry,
					"placeholder": "Please select an IP group",
					"hint":        "",
				},
			},
			{
				"type":                 "ip_belongs",
				"text":                 "IP location",
				"operators":            []string{"in", "not_in"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "area_select",
					"value":       "",
					"placeholder": "please select the region",
					"hint":        "",
				},
			},
			{
				"type":                 "method",
				"text":                 "Method",
				"operators":            []string{"eq", "neq", "in", "not_in"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type": "select",
					"value": []map[string]any{
						{
							"key":   "GET",
							"label": "GET",
						},
						{
							"key":   "POST",
							"label": "POST",
						},
						{
							"key":   "PUT",
							"label": "PUT",
						},
						{
							"key":   "DELETE",
							"label": "DELETE",
						},
						{
							"key":   "PATCH",
							"label": "PATCH",
						},
						{
							"key":   "TRACE",
							"label": "TRACE",
						},
						{
							"key":   "HEAD",
							"label": "HEAD",
						},
						{
							"key":   "OPTIONS",
							"label": "OPTIONS",
						},
						{
							"key":   "CONNECT",
							"label": "CONNECT",
						},
					},
					"placeholder": "Please select request method",
					"hint":        "",
				},
			},
			{
				"type":                 "uri",
				"text":                 "URI path",
				"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp", "in", "not_in"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": "Please enter URI",
					"hint":        "e.g. /index.php",
				},
			},
			{
				"type":                 "uri_with_param",
				"text":                 "URI",
				"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp", "in", "not_in"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": "Please enter URI",
					"hint":        "e.g. /index.php?username=xiaoming",
				},
			},
			{
				"type":                 "param_name",
				"text":                 "URI param name",
				"operators":            []string{"in", "not_in"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": "Please enter parameter name",
					"hint":        "e.g. username",
				},
			},
			{
				"type":                 "param",
				"text":                 "URI param",
				"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp"},
				"left_factor_enabled":  true,
				"right_factor_enabled": true,
				"left_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": "Please enter parameter name",
					"hint":        "e.g. username",
				},
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": "Please enter parameter value",
					"hint":        "e.g. Jack",
				},
			},
			{
				"type":                 "request_header",
				"text":                 "Header",
				"operators":            []string{"eq", "neq", "prefix", "suffix", "like", "regexp"},
				"left_factor_enabled":  true,
				"right_factor_enabled": true,
				"left_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": "Please enter the request header name",
					"hint":        "e.g. Host",
				},
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": "Please enter matching value",
					"hint":        "e.g. www.bt.cn",
				},
			},
			{
				"type":                 "user-agent",
				"text":                 "User Agent",
				"operators":            []string{"eq", "neq", "like"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": "Please enter matching value",
					"hint":        "e.g. Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6)...",
				},
			},
			{
				"type":                 "referer",
				"text":                 "Referer",
				"operators":            []string{"eq", "neq", "in", "not_in", "prefix", "suffix", "regexp"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": "Please enter matching value",
					"hint":        "e.g. https://www.bt.cn/",
				},
			},
			{
				"type":                 "request_header_name",
				"text":                 "Request header name",
				"operators":            []string{"in", "not_in"},
				"left_factor_enabled":  false,
				"right_factor_enabled": true,
				"left_widget":          make(map[string]any),
				"right_widget": map[string]any{
					"type":        "text",
					"value":       "",
					"placeholder": "Please enter the request header name",
					"hint":        "e.g. Host",
				},
			},
		},

		"operators": map[string]map[string]any{
			"regexp": {
				"text":      "Regex",
				"data_type": "string",
			},
			"prefix": {
				"text":      "Prefix",
				"data_type": "string",
			},
			"suffix": {
				"text":      "Suffix",
				"data_type": "string",
			},
			"like": {
				"text":      "Like",
				"data_type": "string",
			},
			"eq": {
				"text":      "eq",
				"data_type": "string",
			},
			"neq": {
				"text":      "neq",
				"data_type": "string",
			},
			"in": {
				"text":      "in",
				"data_type": "set",
			},
			"not_in": {
				"text":      "not in",
				"data_type": "set",
			},
			"gt": {
				"text":      "gt",
				"data_type": "number",
			},
			"egt": {
				"text":      "egt",
				"data_type": "number",
			},
			"lt": {
				"text":      "lt",
				"data_type": "number",
			},
			"elt": {
				"text":      "elt",
				"data_type": "number",
			},
		},
		"sitemap": sitemap,
	})
}

func (c *Customize) Export(request *http.Request) core.Response {
	rules := c.loadRules()
	bs, err := json.Marshal(rules)
	if err != nil {
		return core.Fail(err)
	}
	return core.Download(core.Lan("modules.customize.export_file_name")+time.Now().Format("2006-01-02")+".json", bs)
}

func (c *Customize) Import(request *http.Request) core.Response {
	err := request.ParseMultipartForm(50 << 10)
	if err != nil {
		return core.Fail(core.Lan("modules.customize.import.fail.size"))
	}
	f, fh, err := request.FormFile("customize_rule")
	if err != nil {
		return core.Fail(core.Lan("modules.customize.import.fail.read") + err.Error())
	}
	defer f.Close()
	if !strings.HasSuffix(fh.Filename, ".json") {
		return core.Fail(core.Lan("modules.customize.import.fail.invalid_1"))
	}
	bs, err := io.ReadAll(f)
	if err != nil {
		return core.Fail(core.Lan("modules.customize.import.fail.invalid_2"))
	}
	if len(bs) == 0 {
		return core.Fail(core.Lan("modules.customize.import.empty_file"))
	}
	data := make([]types.Entry, 0)
	if err := json.Unmarshal(bs, &data); err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.customize.import.format.error"), err))
	}
	if len(data) == 0 {
		return core.Fail(core.Lan("modules.customize.import.empty_data"))
	}
	_, err = public.SqliteWithClose(func(conn *db.Sqlite) (res any, err error) {
		conn.Begin()
		defer func() {
			if err != nil {
				conn.Rollback()
				return
			}
			conn.Commit()
		}()
		for _, entry := range data {
			if entry.Id == 0 {
				return nil, errors.New(core.Lan("modules.customize.import.invalid_data"))
			}
			rawData, err := entry.ToEntryFromDatabase()
			if err != nil {
				return nil, err
			}
			rawData.Name += "__FROM_IMPORT"
			insertData := public.StructToMap(rawData)
			delete(insertData, "id")
			id, err := conn.NewQuery().Table("customize_rules").Insert(insertData)
			if err != nil {
				return nil, err
			}
			if rawData.IsGlobal == 0 && len(entry.Servers) > 0 {
				insertAll := make([]types.WebsiteRuleLink, 0)
				for _, v := range entry.Servers {
					insertAll = append(insertAll, types.WebsiteRuleLink{
						RuleId:     int(id),
						ServerName: v,
					})
				}
				_, err = conn.NewQuery().Table("customize_rule_website").InsertAll(common.SliceToSliceMap(insertAll), db.EXTRA_IGNORE)
				if err != nil {
					return nil, err
				}
			}
		}
		return nil, nil
	})
	if err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.customize.import.db.fail"), err))
	}
	if err := c.syncConfigFile(); err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.customize.import.sync.fail"), err))
	}
	return core.Success(core.Lan("modules.customize.import.success"))
}

func (c *Customize) ToExpression(request *http.Request) core.Response {
	params := struct {
		Id int `json:"id"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.Id == 0 {
		return core.Fail(core.Lan("modules.customize.rule_id.empty"))
	}
	if !public.S("customize_rules").Where("id = ?", []any{params.Id}).Exists() {
		return core.Fail(core.Lan("modules.customize.rule.not_found"))
	}
	rawData := types.EntryFromDatabase{}
	err := public.S("customize_rules").
		Where("id = ?", []any{params.Id}).
		Field([]string{"id", "is_global", "status", "priority", "create_time", "execute_phase", "name", "servers", "action", "root"}).
		FindAs(&rawData)
	if err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.customize.to_expr.db.fail"), err))
	}
	entry, err := rawData.ToEntry()
	if err != nil {
		return core.Fail(fmt.Errorf(core.Lan("modules.customize.to_expr.rule.fail"), err))
	}
	return core.Success(entry.ToExpression())
}

func (c *Customize) CreateWithBlockLog(request *http.Request) core.Response {
	type Params struct {
		ServerName string `json:"server_name"`
		Uri        string `json:"uri"`
		Method     string `json:"method"`
	}
	type ParamsListData struct {
		Data []Params `json:"data"`
	}
	List := ParamsListData{}
	if err := core.GetParamsFromRequestToStruct(request, &List); err != nil {
		return core.Fail(err)
	}
	paramsList := List.Data
	successList := 0
	failList := 0
	sameMap := make(map[string]string, 0)
	for _, params := range paramsList {
		if params.ServerName == "" {
			failList++
			continue
		}

		if params.Uri == "" {
			failList++
			continue
		}

		if params.Method == "" {
			failList++
			continue
		}
		keyword := params.ServerName + params.Uri + params.Method
		if _, ok := sameMap[keyword]; ok {
			continue
		} else {
			sameMap[keyword] = "1"
		}
		params.Uri = html.UnescapeString(params.Uri)
		node := &types.Node{
			Type:     "block",
			Logic:    "and",
			Children: make([]*types.Node, 0),
		}
		u, err := url.ParseRequestURI(params.Uri)
		if err != nil {
			failList++
			continue
		}
		node.Children = append(node.Children, &types.Node{
			Type:     "option",
			Children: make([]*types.Node, 0),
			Option: &types.Option{
				Type:        "method",
				Operator:    "eq",
				RightFactor: strings.ToUpper(params.Method),
			},
		})
		node.Children = append(node.Children, &types.Node{
			Type:     "option",
			Children: make([]*types.Node, 0),
			Option: &types.Option{
				Type:        "uri",
				Operator:    "eq",
				RightFactor: u.Path,
			},
		})
		paramNameLst := make([]string, 0)
		for k := range u.Query() {
			paramNameLst = append(paramNameLst, k)
		}
		if len(paramNameLst) > 0 {
			node.Children = append(node.Children, &types.Node{
				Type:     "option",
				Children: make([]*types.Node, 0),
				Option: &types.Option{
					Type:        "param_name",
					Operator:    "in",
					RightFactor: strings.Join(paramNameLst, ","),
				},
			})
		}
		entry := types.Entry{
			Name:       core.Lan("modules.customize.url_whitelist_name") + params.Uri,
			Servers:    []string{params.ServerName},
			CreateTime: time.Now().Unix(),
			Status:     1,
			Src:        1,
			Action: &types.Action{
				Type:     "allow",
				Response: &types.Response{},
			},
			Root: &types.Node{
				Type:     "block",
				Logic:    "or",
				Children: []*types.Node{node},
			},
		}
		rawData, err := entry.ToEntryFromDatabase()

		if err != nil {
			failList++
			continue
		}
		insertData := public.StructToMap(rawData)
		delete(insertData, "id")
		_, err = public.SqliteWithClose(func(conn *db.Sqlite) (res any, err error) {
			conn.Begin()
			defer func() {
				if err != nil {
					conn.Rollback()
					return
				}
				conn.Commit()
			}()
			id, err := conn.NewQuery().Table("customize_rules").Insert(insertData)
			if err != nil {
				return nil, err
			}
			if rawData.IsGlobal == 0 && len(entry.Servers) > 0 {
				insertAll := make([]types.WebsiteRuleLink, 0)
				for _, v := range entry.Servers {
					insertAll = append(insertAll, types.WebsiteRuleLink{
						RuleId:     int(id),
						ServerName: v,
					})
				}
				_, err = conn.NewQuery().Table("customize_rule_website").InsertAll(common.SliceToSliceMap(insertAll), db.EXTRA_IGNORE)
				if err != nil {
					return nil, err
				}
			}
			return nil, nil
		})
		if err != nil {
			failList++
			continue
		}
		if err := c.syncConfigFile(); err != nil {
			failList++
			continue
		}
		successList++
	}
	if successList > 0 {
		return core.Success(fmt.Sprintf(core.Lan("modules.customize.add_url_whitelist.success"), strconv.Itoa(successList), strconv.Itoa(failList)))
	} else {
		return core.Fail(fmt.Sprintf(core.Lan("modules.customize.add_url_whitelist.success"), strconv.Itoa(successList), strconv.Itoa(failList)))
	}
}

func (c *Customize) loadRules() (lst []types.Entry) {
	res := make([]types.EntryFromDatabase, 0)

	err := public.S("customize_rules").
		Field([]string{"id", "is_global", "status", "priority", "create_time", "execute_phase", "name", "servers", "action", "root", "src"}).
		SelectAs(&res)

	if err != nil {
		return lst
	}

	for _, v := range res {
		entry, err := v.ToEntry()

		if err != nil {
			continue
		}

		lst = append(lst, *entry)
	}
	return lst
}

func (c *Customize) syncConfigFile() (err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	rules := c.loadRules()
	m := make(map[string]types.Entry)
	globalRuleIds := make([]string, 0)
	websiteRuleIdMap := make(map[string][]string)
	websiteRuleLinked := make([]struct {
		RuleId     int    `json:"rule_id"`
		ServerName string `json:"server_name"`
	}, 0)
	err = public.S("customize_rule_website").
		Field([]string{"rule_id", "server_name"}).
		SelectAs(&websiteRuleLinked)
	if err != nil {
		return err
	}
	for _, v := range rules {
		ruleId := strconv.Itoa(v.Id)
		m[ruleId] = v
		if v.IsGlobal == 1 {
			globalRuleIds = append(globalRuleIds, ruleId)
		}
	}
	for _, v := range websiteRuleLinked {
		if _, ok := websiteRuleIdMap[v.ServerName]; !ok {
			websiteRuleIdMap[v.ServerName] = make([]string, 0)
		}
		ruleId := strconv.Itoa(v.RuleId)
		if _, ok := m[ruleId]; !ok {
			continue
		}
		websiteRuleIdMap[v.ServerName] = append(websiteRuleIdMap[v.ServerName], ruleId)
	}
	data := map[string]any{
		"rules":   m,
		"allsite": globalRuleIds,
	}
	for k, v := range websiteRuleIdMap {
		data[k] = v
	}
	bs, err := json.Marshal(data)
	if err != nil {
		return err
	}
	err = os.WriteFile(public.CUSTOMIZE_RULE_FILE, bs, 0644)

	if err != nil {
		return err
	}
	_, err = public.HttpPostByToken("http://127.0.0.251/updateinfo?types=config", 2)
	if err != nil {
		return err
	}
	return nil
}

func (c *Customize) parseExpression(expr string) *types.Node {
	chunks := c.logicOrRegexp.Split(strings.TrimSpace(expr), -1)
	root := types.Node{
		Type:     "block",
		Logic:    "or",
		Children: make([]*types.Node, 0),
	}
	for i, chunk := range chunks {
		chunk = strings.TrimPrefix(chunk, "(")
		chunk = strings.TrimSuffix(chunk, ")")
		chunk = strings.TrimSpace(chunk)
		subExprs := c.logicAndRegexp.Split(chunk, -1)
		root.Children = append(root.Children, &types.Node{
			Type:     "block",
			Logic:    "and",
			Children: make([]*types.Node, 0),
		})
		for _, subExpr := range subExprs {
			matched := c.exprReg.FindStringSubmatch(subExpr)
			if len(matched) < 4 {
				continue
			}
			leftFactor := ""
			parts := strings.SplitN(strings.TrimSpace(matched[1]), ".", 2)
			optionType := strings.TrimSpace(parts[0])
			if len(parts) > 1 {
				leftFactor = strings.TrimSpace(parts[1])
			}
			operator, ok := c.operatorMap[matched[2]]
			if !ok {
				continue
			}
			rightFactor := strings.TrimSpace(matched[3])
			if operator == "in" || operator == "not_in" {
				rightFactor = strings.Trim(rightFactor, "{}")
				rightFactor = strings.TrimSpace(rightFactor)
				rawLst := strings.Split(rightFactor, ",")
				lst := make([]string, 0)
				for _, v := range rawLst {
					v = strings.TrimSpace(v)
					v = strings.Trim(v, `"'`)
					v = strings.TrimSpace(v)
					lst = append(lst, v)
				}
				rightFactor = strings.Join(lst, ",")
			} else {
				rightFactor = strings.Trim(strings.TrimSpace(matched[3]), `"'`)
			}
			root.Children[i].Children = append(root.Children[i].Children, &types.Node{
				Type:  "option",
				Logic: "",
				Option: &types.Option{
					Type:        optionType,
					LeftFactor:  leftFactor,
					Operator:    operator,
					RightFactor: rightFactor,
				},
				Children: make([]*types.Node, 0),
			})
		}
	}
	return &root
}

func (c *Customize) ExportExample(request *http.Request) core.Response {
	type example struct {
		LeftFactor  string `json:"left_factor"`
		RightFactor string `json:"right_factor"`
	}

	type option struct {
		Type      string             `json:"type"`
		Text      string             `json:"text"`
		Operators []string           `json:"operators"`
		Examples  map[string]example `json:"examples"`
	}

	optTrans := map[string]string{
		"regexp": core.Lan("modules.customize.regexp"),
		"prefix": core.Lan("modules.customize.match_start.prefix"),
		"suffix": core.Lan("modules.customize.match_end.suffix"),
		"like":   core.Lan("modules.customize.like.keyword"),
		"eq":     core.Lan("modules.customize.eq.equal"),
		"neq":    core.Lan("modules.customize.neq.not_equal"),
		"in":     core.Lan("modules.customize.in.incloud"),
		"not_in": core.Lan("modules.customize.not_in.not_incloud"),
		"gt":     core.Lan("modules.customize.gt.greater_than"),
		"egt":    core.Lan("modules.customize.egt.greater_than_or_equal"),
		"lt":     core.Lan("modules.customize.lt.less_than"),
		"elt":    core.Lan("modules.customize.elt.less_than_or_equal"),
	}
	params := struct {
		Options []option `json:"options"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}

	rules := make(map[string]types.Entry, 0)
	allsite := make([]string, 0)

	maxId := 1
	curTime := time.Now().Unix()

	action := types.Action{
		Type: "record",
	}
	for _, op := range params.Options {
		for _, opt := range op.Operators {
			examp, ok := op.Examples[opt]

			if !ok {
				continue
			}

			name := op.Text

			if examp.LeftFactor != "" {
				name += "__" + examp.LeftFactor
			}

			name += "__" + optTrans[opt]

			if opt == "in" || opt == "not_in" {
				name += "__" + "{" + examp.RightFactor + "}"
			} else {
				name += "__" + examp.RightFactor
			}

			maxIdStr := strconv.Itoa(maxId)
			rules[maxIdStr] = types.Entry{
				Id:           maxId,
				Name:         name,
				Servers:      make([]string, 0),
				CreateTime:   curTime,
				Status:       1,
				IsGlobal:     1,
				ExecutePhase: "access",
				Action:       &action,
				Root: &types.Node{
					Type:  "block",
					Logic: "or",
					Children: []*types.Node{
						{
							Type: "option",
							Option: &types.Option{
								Type:        op.Type,
								LeftFactor:  examp.LeftFactor,
								Operator:    opt,
								RightFactor: examp.RightFactor,
							},
							Children: make([]*types.Node, 0),
						},
					},
				},
			}
			allsite = append(allsite, maxIdStr)

			maxId++
		}
	}
	return core.Success(map[string]any{
		"rules":   rules,
		"allsite": allsite,
	})
}
