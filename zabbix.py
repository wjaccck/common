import requests,json,argparse
import time,threadpool
class Zabbix_api:
    api_url='http://hz.zabbix.ejuops.com/api_jsonrpc.php'
    auth_id=None
    auth_key=None
    all_host=None
    def __init__(self,user,password):
        self.header={"Content-Type": "application/json"}
        auth_id_result=self._get_auth_id(user=user,password=password)
        self.auth_key=auth_id_result.get('result')
        self.auth_id = auth_id_result.get('id')
        self.all_host=self._get_all_host()
    def get(self, path):
        result=requests.get(path,headers=self.header)
        return result.status_code,result.json()

    def post(self,path,data):
        result=requests.post(path,data=json.dumps(data),headers=self.header)
        return result.status_code,result.json()

    def _get_auth_id(self,user,password):
        data = {
            "jsonrpc": "2.0",
            "method": "user.login",
            "params": {
                "user": user,
                "password": password
            },
            "id": 1
        }
        _,result = self.post(self.api_url,data=data)
        return result

    def _get_all_host(self):
        all_host={}
        data = {
            "jsonrpc": "2.0",
            "method": "host.get",
            "params": {
                "output": [
                    "hostid",
                    "host"
                ],
                "selectInterfaces": [
                    "interfaceid",
                    "ip"
                ]
            },
            "id": self.auth_id,
            "auth": self.auth_key,

        }

        _,result = self.post(self.api_url,data=data)
        for m in result.get('result'):
            m_host_id = m.get('hostid', None)
            m_ip = m.get('interfaces')[0].get('ip', None)
            all_host[m_ip]=m_host_id

        return all_host
    def _get_host_id(self,host):
        return self.all_host.get(host)

    def _get_itemid(self,host_id,key_):
        data={
                "jsonrpc": "2.0",
                "method": "item.get",
                "params": {
                    "output": "extend",
                    "hostids": host_id,
                    "search": {
                        "key_": key_
                    },
                    "sortfield": "name"
                },
                "auth": self.auth_key,
                "id": self.auth_id
            }
        _,result=self.post(self.api_url,data=data)
        itemid=result.get('result')[0].get('itemid')
        return itemid
    def _get_history_avg(self,itemid):
        data={
            "jsonrpc": "2.0",
            "method":"history.get",
            "params":{
                "history":0,
                "itemids":[itemid],
                "time_from":"1511539200",
                "time_till":"1514131200",
                "output":"extend"},
            "auth": self.auth_key,
            "id": self.auth_id
        }
        _,result=self.post(self.api_url,data=data)
        total_data = [float(x.get('value')) for x in result.get('result')]
        data_avg = sum(total_data) / total_data.__len__()
        return data_avg
    def get_info(self,host):

        cpu_key = 'system.cpu.util[,idle]'
        memory_usepercent_key = 'vm.memory.usepercent'
        # memory_totla_key = 'vm.memory.size[total]'
        # memory_available_key = 'vm.memory.size[available]'
        host_id=self._get_host_id(host=host)
        cpu_id=self._get_itemid(host_id=host_id,key_=cpu_key)
        memory_usepercent_id=self._get_itemid(host_id=host_id,key_=memory_usepercent_key)
        # memory_total_id=self._get_itemid(host_id=host_id,key_=memory_totla_key)
        # memory_avaliable_id=self._get_itemid(host_id=host_id,key_=memory_available_key)
        cpu_avg=self._get_history_avg(cpu_id)
        memory_usepercent_avg=self._get_history_avg(memory_usepercent_id)
        # memory_total_avg=self._get_history_avg(memory_total_id)
        # memory_avaliable_avg=self._get_history_avg(memory_avaliable_id)
        data={}
        data[host]={
            "cpu":cpu_avg,
            # "memory_total":memory_total_avg,
            # "memory_avaliable": memory_avaliable_avg,
            "memory_usepercent": memory_usepercent_avg,
            # "memory_avaliable_percent":(memory_avaliable_avg/memory_total_avg)*100
        }
        return data

if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description="your script description")
    # parser.add_argument('--host', required=True, type=str)
    # args = parser.parse_args()
    # host=args.host
    # a=Zabbix_api(user='jinhongjun',password='jinhongjun')
    # result=a.get_info(host=host)
    # print result
    with open('list.txt') as f:
      all_list=[x.strip() for x in f.readlines()]
    start_time = time.time()
    pool = threadpool.ThreadPool(20)
    requests = threadpool.makeRequests(Zabbix_api(user='jinhongjun',password='jinhongjun').get_info, all_list)
    [pool.putRequest(req) for req in requests]
    pool.wait()
    print '%d second'% (time.time()-start_time)