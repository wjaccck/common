import psutil, time
import httplib,json,argparse
TOKEN='1ebc65060715bfa1c0af8f0684b68a51cd775451'
SITE='http://unknown/procs/'
HEADERS={"Authorization": "Token {0}".format(TOKEN), "Content-Type": "application/json"}

import requests,json
### sigle rest request
class Django_rest_api:
    def __init__(self):
        self.header={"Authorization": "Token {0}".format(TOKEN), "Content-Type": "application/json"}

    def get(self, path):
        result=requests.get(path,headers=self.header)
        return result.status_code,result.json()
    def post(self,path,data):
        result=requests.post(path,data=json.dumps(data),headers=self.header)
        return result.status_code,result.json()
    def put(self,path,data):
        result=requests.put(path,data=json.dumps(data),headers=self.header)
        return result.status_code,result.json()
    def patch(self,path,data):
        result=requests.patch(path,data=json.dumps(data),headers=self.header)
        return result.status_code,result.json()
    def delete(self,path,data):
        result=requests.delete(path,headers=self.header)
        return result.status_code,result.json()

def getAllProcessInfo(host):
    instances = []
    for proc in psutil.process_iter(attrs=['pid', 'name', 'username']):
        instances.append(proc.info)
    send_data={
        "host":host,
        "procs":instances
    }
    ret_status,ret_result=Django_rest_api().post(SITE,send_data)
    print ret_status
    print ret_result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="your script description")
    parser.add_argument('--host', required=True, type=str)
    args = parser.parse_args()
    host=args.host
    getAllProcessInfo(host=host)