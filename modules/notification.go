package modules

import (
	"CloudWaf/core"
	"CloudWaf/public"
	"CloudWaf/public/notification"
	"CloudWaf/public/validate"
	"errors"
	"net/http"
)

func init() {

	core.RegisterModule(&Notification{})
}

type Notification struct{}

func (n *Notification) List(request *http.Request) core.Response {
	email := notification.DefaultEmailNotifier()
	dingding := notification.DefaultDingDingNotifier()
	feishu := notification.DefaultFeiShuNotifier()
	weixin := notification.DefaultWeiXinNotifier()
	return core.Success([]interface{}{
		map[string]interface{}{
			"name":          core.Lan("modules.notification.email"),
			"type":          "email",
			"is_configured": email.IsConfigured(),
			"config":        email,
		},
		map[string]interface{}{
			"name":          core.Lan("modules.notification.dingding"),
			"type":          "dingding",
			"is_configured": dingding.IsConfigured(),
			"config":        dingding,
		},
		map[string]interface{}{
			"name":          core.Lan("modules.notification.feishu"),
			"type":          "feishu",
			"is_configured": feishu.IsConfigured(),
			"config":        feishu,
		},
		map[string]interface{}{
			"name":          core.Lan("modules.notification.weixin"),
			"type":          "weixin",
			"is_configured": weixin.IsConfigured(),
			"config":        weixin,
		},
	})
}

func (n *Notification) Update(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)

	if err != nil {
		return core.Fail(err)
	}
	notificationType := ""
	config := make(map[string]interface{})
	if v, ok := params["type"]; ok {
		notificationType = public.InterfaceToString(v)
	}

	if notificationType == "" {
		return core.Fail(core.Lan("modules.notification.type.missing"))
	}
	if v, ok := params["config"]; ok {
		config, _ = v.(map[string]interface{})
	}

	if len(config) == 0 {
		return core.Fail(core.Lan("modules.notification.config.missing"))
	}
	err = n.updateConfig(notificationType, config)

	if err != nil {
		return core.Fail(err)
	}

	return core.Success("ok")
}

func (n *Notification) Clear(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	notificationType := ""
	if v, ok := params["type"]; ok {
		notificationType = public.InterfaceToString(v)
	}
	if notificationType == "" {
		return core.Fail(core.Lan("modules.notification.type.missing"))
	}
	notifier, err := notification.Notifier(notificationType)

	if err != nil {
		return core.Fail(err)
	}
	err = notifier.ClearConfig()

	if err != nil {
		return core.Fail(err)
	}
	return core.Success(core.Lan("modules.notification.op.success"))
}

func (n *Notification) updateConfig(notificationType string, config map[string]interface{}) (err error) {

	msg := notification.Message{core.Lan("modules.notification.test.title"), []string{
		core.Lan("modules.notification.test.msg1"),
		core.Lan("modules.notification.test.msg2"),
	}}

	switch notificationType {
	case "email":
		if _, ok := config["email"]; !ok {
			return errors.New(core.Lan("modules.notification.email.email.missing"))
		}

		if _, ok := config["host"]; !ok {
			return errors.New(core.Lan("modules.notification.email.host.missing"))
		}

		if _, ok := config["port"]; !ok {
			return errors.New(core.Lan("modules.notification.email.port.missing"))
		}

		if _, ok := config["password"]; !ok {
			return errors.New(core.Lan("modules.notification.email.password.missing"))
		}

		if _, ok := config["receivers"]; !ok {
			return errors.New(core.Lan("modules.notification.email.receivers.missing"))
		}
		email := notification.DefaultEmailNotifier()
		if v, ok := config["email"].(string); ok {
			if !validate.IsEmail(v) {
				return errors.New(core.Lan("modules.notification.email.email.format.error") + v)
			}

			email.Email = v
		}
		if v, ok := config["host"].(string); ok {
			if !validate.IsHost(v) {
				return errors.New(core.Lan("modules.notification.email.host.format.error") + v)
			}

			email.Host = v
		}
		if v, ok := config["port"].(string); ok {
			if !validate.IsPort(v) {
				return errors.New(core.Lan("modules.notification.email.port.format.error") + v)
			}
			email.Port = v
		}
		if v, ok := config["password"].(string); ok {
			email.Password = v
		}
		if v, ok := config["receivers"].([]interface{}); ok {
			receivers := public.InterfaceArray_To_StringArray(v)
			for _, receiver := range receivers {
				if !validate.IsEmail(receiver) {
					return errors.New(core.Lan("modules.notification.email.receiver.format.error") + receiver)
				}
			}

			if len(receivers) == 0 {
				return errors.New(core.Lan("modules.notification.email.receiver.empty"))
			}

			email.Receivers = receivers
		}
		err = email.Notify(msg)
		if err != nil {
			return err
		}
		return email.UpdateConfig()
	case "dingding":
		if _, ok := config["url"]; !ok {
			return errors.New(core.Lan("modules.notification.dingding.url.missing"))
		}
		dingding := notification.DefaultDingDingNotifier()
		if v, ok := config["url"].(string); ok {
			if !validate.IsUrl(v) {
				return errors.New(core.Lan("modules.notification.url.format.error") + v)
			}

			dingding.Url = v
		}
		err = dingding.Notify(msg)

		if err != nil {
			return err
		}
		return dingding.UpdateConfig()
	case "feishu":
		if _, ok := config["url"]; !ok {
			return errors.New(core.Lan("modules.notification.feishu.url.missing"))
		}
		feishu := notification.DefaultFeiShuNotifier()
		if v, ok := config["url"].(string); ok {
			if !validate.IsUrl(v) {
				return errors.New(core.Lan("modules.notification.url.format.error") + v)
			}

			feishu.Url = v
		}
		err = feishu.Notify(msg)
		if err != nil {
			return err
		}
		return feishu.UpdateConfig()
	case "weixin":
		if _, ok := config["url"]; !ok {
			return errors.New(core.Lan("modules.notification.weixin.url.missing"))
		}

		weixin := notification.DefaultWeiXinNotifier()
		if v, ok := config["url"].(string); ok {
			if !validate.IsUrl(v) {
				return errors.New(core.Lan("modules.notification.url.format.error") + v)
			}

			weixin.Url = v
		}
		err = weixin.Notify(msg)

		if err != nil {
			return err
		}
		return weixin.UpdateConfig()
	default:
		return errors.New(core.Lan("modules.notification.unsupported") + notificationType)
	}
}
