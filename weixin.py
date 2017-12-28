#!/usr/bin/python
import string
import commands
import httplib
import platform
import datetime

if platform.python_version().startswith('2.4'):
    import simplejson as json
else:
    import json


class Rest_api:
    def __init__(self):
        self.header = {"Authorization": "Token 8fa24e8bf724654f25edd3b31d7d08242440f5db",
                       "Content-Type": "application/json"}

    def create(self, path, data):
        conn = httplib.HTTPConnection('10.0.8.131', 9000)
        conn.connect()
        content = json.dumps(data)
        conn.request('POST', path, content, self.header)
        result = conn.getresponse()
        conn.close()
        return result.status, result.read()

    def get(self, path):
        conn = httplib.HTTPConnection('10.0.8.131', 9000)
        conn.connect()
        conn.request('GET', path, '', self.header)
        result = conn.getresponse()
        conn.close()
        return result.status, json.loads(result.read())

    def update(self, path, data):
        conn = httplib.HTTPConnection('10.0.8.131', 9000)
        conn.connect()
        content = json.dumps(data)
        conn.request('PATCH', path, content, self.header)
        result = conn.getresponse()
        conn.close()
        return result.status, result.read()

    def delete(self, path):
        conn = httplib.HTTPConnection('10.0.8.131', 9000)
        conn.connect()
        conn.request('DELETE', path, '', self.header)
        result = conn.getresponse()
        conn.close()
        return result.status, result.read()


class Send_message(object):
    def __init__(self):
        self.header = {"Content-Type": "application/json"}
        self.host = 'qyapi.weixin.qq.com'
        self._get_token()
        # https://oapi.dingtalk.com/gettoken?corpid=id&corpsecret=secrect

    def _get_token(self):
        headers = {"Content-Type": "application/xml"}
        conn = httplib.HTTPSConnection(self.host, 443)
        conn.connect()
        conn.request('GET',
                     '/cgi-bin/gettoken?corpid=wx5d299f9a3fba1d89&corpsecret=TZOFryL5qR8SnBlwKszOdrMnCxR6dDZH1NAX-mvtXfwawuCAPwoUuOu0w2rz8MRd',
                     '', headers)
        result = conn.getresponse().read()
        self.token = json.loads(result).get('access_token')

    def _send_msg(self, msg):
        headers = {"Content-Type": "application/xml"}
        conn = httplib.HTTPSConnection(self.host, 443)
        conn.connect()
        data = {
            "touser": "ymt0361",
            "msgtype": "text",
            "agentid": 3,
            "text": {
                "content": msg
            },
            "safe": 0
        }
        content = json.dumps(data)
        conn.request('POST', '/cgi-bin/message/send?access_token=%s' % self.token, content, headers)
        result = conn.getresponse().read()
        conn.close()
        return json.loads(result)

    def run(self, msg):
        result = self._send_msg(msg)
        print result


def main():
    # msg=Rest_api().get('/api/history.json?created_date=')
    # Console().run(result)
    nn = datetime.datetime.now().strftime('%Y-%m-%d')
    # nn='2016-11-22'
    query_url = "/api/history.json?current_date={0}".format(nn)
    #    query_url="/api/history.json?current_date=2017-02-08"
    status, result = Rest_api().get(query_url)
    print status
    print result
    if result.get('count') != 0:
        msg = '\r\n'.join(["{0} {1} {2} {3}".format(x.get('ip'), x.get('port'), x.get('proc'), x.get('status')) for x in
                           result.get('results')])
        print msg
        Send_message().run(msg)


if __name__ == "__main__":
    main()