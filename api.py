# coding: utf-8
import time
import hashlib
import json
import requests


class WafApi:
    __WAF_KEY = 'op51JCeKAdqa7AUtKae7ONrMeW8FdAWA'
    __WAF_PANEL = 'https://192.168.10.10:8379'

    def __get_md5(self, s: str) -> str:
        """计算字符串的 MD5 值"""
        return hashlib.md5(s.encode('utf-8')).hexdigest()

    def __get_headers(self) -> dict:
        """生成请求头中的 waf_request_time 和 waf_request_token"""
        time_now = str(int(time.time()))
        token = self.__get_md5(time_now + self.__get_md5(self.__WAF_KEY))
        return {
            'waf_request_time': time_now,
            'waf_request_token': token,
            "Content-Type":"application/json"
        }

    def get_logs(self):
        """获取站点日志列表"""
        url = f"{self.__WAF_PANEL}/api/wafmastersite/get_site_list"
        headers = self.__get_headers()
        payload = {'p': 1, 'p_size': 20, 'site_name': ""}

        try:
            response = requests.post(
                url,
                headers=headers,
                data=json.dumps(payload),
                timeout=10,
                verify=False
            )

            if response.status_code == 200:
                json_data = response.json()
                if json_data.get('code') == 0:
                    return json_data
                else:
                    print("接口返回失败:", json_data.get('msg', '未知错误'))
            else:
                print(f"请求失败，状态码：{response.status_code}")
                print("请检查当前IP是否 在API访问白名单内")

        except requests.RequestException as e:
            print(f"网络请求异常: {e}")

        return None


if __name__ == '__main__':
    waf_api = WafApi()
    logs = waf_api.get_logs()
    print(logs)