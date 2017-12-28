#coding=utf-8
import requests,json,httplib
import xlwt,xlrd
import paramiko
import json
import jenkins

import json, sys, os
from collections import namedtuple
from ansible.parsing.dataloader import DataLoader
from ansible.vars import VariableManager
from ansible.inventory import Inventory, Host, Group
from ansible.playbook.play import Play
from ansible.executor.task_queue_manager import TaskQueueManager
from ansible.plugins.callback import CallbackBase
from ansible.executor.playbook_executor import PlaybookExecutor

def get_json(file):
    ''' 获取json文件'''
    with open(file, 'r') as f:
      content=f.read()
    return json.loads(content)



def get_result(retcode, result):
    if retcode == 0:
        return dict(retcode=retcode, stderr='', stdout=result)
    else:
        return dict(retcode=retcode, stderr=result, stdout='')




### sigle rest request
class Django_rest_api:
    '''获取django rest framework api的数据'''
    def __init__(self,token):
        self.header={"Authorization": "Token {0}".format(token), "Content-Type": "application/json"}

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

##django rest framework get all
class Get_all(object):
    '''获取指定url的所有数据'''
    result=[]
    def __init__(self,token):
        self.api=Django_rest_api(token)
    def _get(self,url):
        retcode,http_result=self.api.get(url)
        if retcode==200:
            self.result.extend(http_result.get('results'))
            if http_result.get('next') is None:
                pass
            else:
                return self._get(http_result.get('next'))
        else:
            return

    def get_all(self,url):
        self._get(url)
        return self.result

class Wbk(object):
    '''数据写入excel表格[['a','b'],['c','d']]'''
    def __init__(self):
        self.wbk = xlwt.Workbook()
    def wt(self,name,data,sheet_name='sheet 1'):
        self.sheet = self.wbk.add_sheet(sheet_name)
        for number in range(0,len(data)):
            for number_p in range(0,len(data[number])):
                self.sheet.write(number,number_p,data[number][number_p])
        self.wbk.save('{0}.xlsx'.format(name))

class Rbk(object):
    '''读取excel表格，返回列表'''
    def __init__(self,file):
        self.data = xlrd.open_workbook(file)
    def excel_table_byindex(self,colnameindex=0,by_index=0):
        table = self.data.sheets()[by_index]
        nrows = table.nrows
        ncols = table.ncols
        colnames =  table.row_values(colnameindex)
        list =[]
        for rownum in range(1,nrows):
             row = table.row_values(rownum)
             if row:
                 app = {}
                 for i in range(len(colnames)):
                    app[colnames[i]] = row[i]
                 list.append(app)
        return list


class Check_ssh(object):
    '''使用key或者密码通过ssh登录服务器并执行命令'''
    key=None
    def __init__(self,host,user,password,pkey=None):
        self.user=user
        self.password=password
        self.host=host
        self.pkey=pkey
        # self.key=paramiko.RSAKey.from_private_key_file(pkey)
        self.ssh=paramiko.SSHClient()
    def _key_ssh(self,cmd):
        try:
            self.key=paramiko.RSAKey.from_private_key_file(self.pkey)
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(self.host,username = self.user,pkey=self.key)
            stdin,stdout,stderr=self.ssh.exec_command(cmd)
            return get_result(0,stdout.read())
        except Exception,e:
            return get_result(1,str(e))

    def _passwd_ssh(self,cmd):
        try:
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(self.host,username = self.user,password=self.password)
            stdin,stdout,stderr=self.ssh.exec_command(cmd)
            return get_result(0,stdout)
        except Exception,e:
            return get_result(1,str(e))

    def run(self,cmd='id'):
        if self.key:
            return self._key_ssh(cmd)
        else:
            return self._passwd_ssh(cmd)


class Send_msg(object):
    ''' 小饭团自用发送微信消息 '''
    headers={"Content-Type": "application/xml"}
    token=None
    def __init__(self):
        self._get_token()
    def _new_http(self):
        return httplib.HTTPSConnection('qyapi.weixin.qq.com',443)
    def _close_http(self,http):
        return http.close()
    def _get_token(self):
        http=self._new_http()
        http.connect()
        http.request('GET','/cgi-bin/gettoken?corpid=wx5d299f9a3fba1d89&corpsecret=TZOFryL5qR8SnBlwKszOdrMnCxR6dDZH1NAX-mvtXfwawuCAPwoUuOu0w2rz8MRd','',self.headers)
        result=http.getresponse()
        self.token=json.loads(result.read()).get('access_token')
        self._close_http(http)
    def send(self,msg):
        if self.token:
            http=self._new_http()
            send_data={
               "touser": "ymt0361",
               "msgtype": "text",
               "agentid": 3,
               "text": {
                   "content": msg
               },
               "safe":0
            }
            content=json.dumps(send_data)
            http.connect()
            http.request('POST','/cgi-bin/message/send?access_token=%s' %self.token ,content,self.headers)
            tmp_result=http.getresponse().read()
            if tmp_result.get('errcode')==0:
                result=get_result(0,tmp_result.get('errmsg'))
            else:
                result=get_result(1,tmp_result.get('errmsg'))
            self._close_http(http)
        else:
            result=get_result(2,'no token')
        return result


class Console_jenkins(object):
    ''' jenkins 连接，并开始任务，具体可查看
        http://python-jenkins.readthedocs.io/en/latest/api.html
    '''
    def __init__(self,jenkins_server,jenkins_user,jenkins_token):
        self.jenkins_server=jenkins_server
        self.jenkins_user=jenkins_user
        self.jenkins_token=jenkins_token
        self.jenkins = jenkins.Jenkins(jenkins_server
                                 , username=jenkins_user
                                 , password=jenkins_token
                                 )

    def start_job(self,job_name,**kwargs):
        try:
            self.jenkins.build_job(name=job_name,parameters=kwargs, token=self.jenkins_token)
            return get_result(0,'start')
        except Exception,e:
            return get_result(1,str(e))




class MyInventory(Inventory):
    """ 
    this is my ansible inventory object. 
    """

    def __init__(self, resource, loader, variable_manager):
        """ 
        resource的数据格式是一个列表字典，比如 
            { 
                "group1": { 
                    "hosts": [{"hostname": "10.0.0.0", "port": "22", "username": "test", "password": "pass"}, ...], 
                    "vars": {"var1": value1, "var2": value2, ...} 
                } 
            } 

                     如果你只传入1个列表，这默认该列表内的所有主机属于my_group组,比如 
            [{"hostname": "10.0.0.0", "port": "22", "username": "test", "password": "pass"}, ...] 
        """
        self.resource = resource
        self.inventory = Inventory(loader=loader, variable_manager=variable_manager, host_list=[])
        self.dynamic_inventory()

    def add_dynamic_group(self, hosts, groupname, groupvars=None):
        """ 
            add hosts to a group 
        """
        my_group = Group(name=groupname)

        # if group variables exists, add them to group
        if groupvars:
            for key, value in groupvars.iteritems():
                my_group.set_variable(key, value)

                # add hosts to group
        for host in hosts:
            # set connection variables
            hostname = host.get("hostname")
            hostip = host.get('ip', hostname)
            hostport = host.get("port")
            username = host.get("username")
            password = host.get("password")
            ssh_key = host.get("ssh_key")
            my_host = Host(name=hostname, port=hostport)
            my_host.set_variable('ansible_ssh_host', hostip)
            my_host.set_variable('ansible_ssh_port', hostport)
            my_host.set_variable('ansible_ssh_user', username)
            my_host.set_variable('ansible_ssh_pass', password)
            my_host.set_variable('ansible_ssh_private_key_file', ssh_key)

            # set other variables
            for key, value in host.iteritems():
                if key not in ["hostname", "port", "username", "password"]:
                    my_host.set_variable(key, value)
                    # add to group
            my_group.add_host(my_host)

        self.inventory.add_group(my_group)

    def dynamic_inventory(self):
        """ 
            add hosts to inventory. 
        """
        if isinstance(self.resource, list):
            self.add_dynamic_group(self.resource, 'default_group')
        elif isinstance(self.resource, dict):
            for groupname, hosts_and_vars in self.resource.iteritems():
                self.add_dynamic_group(hosts_and_vars.get("hosts"), groupname, hosts_and_vars.get("vars"))

class ModelResultsCollector(CallbackBase):
    def __init__(self, *args, **kwargs):
        super(ModelResultsCollector, self).__init__(*args, **kwargs)
        self.host_ok = {}
        self.host_unreachable = {}
        self.host_failed = {}

    def v2_runner_on_unreachable(self, result):
        self.host_unreachable[result._host.get_name()] = result

    def v2_runner_on_ok(self, result, *args, **kwargs):
        self.host_ok[result._host.get_name()] = result

    def v2_runner_on_failed(self, result, *args, **kwargs):
        self.host_failed[result._host.get_name()] = result

class PlayBookResultsCollector(CallbackBase):
    CALLBACK_VERSION = 2.0

    def __init__(self, *args, **kwargs):
        super(PlayBookResultsCollector, self).__init__(*args, **kwargs)
        self.task_ok = {}
        self.task_skipped = {}
        self.task_failed = {}
        self.task_status = {}
        self.task_unreachable = {}

    def v2_runner_on_ok(self, result, *args, **kwargs):
        self.task_ok[result._host.get_name()] = result

    def v2_runner_on_failed(self, result, *args, **kwargs):
        self.task_failed[result._host.get_name()] = result

    def v2_runner_on_unreachable(self, result):
        self.task_unreachable[result._host.get_name()] = result

    def v2_runner_on_skipped(self, result):
        self.task_ok[result._host.get_name()] = result

    def v2_playbook_on_stats(self, stats):
        hosts = sorted(stats.processed.keys())
        for h in hosts:
            t = stats.summarize(h)
            self.task_status[h] = {
                "ok": t['ok'],
                "changed": t['changed'],
                "unreachable": t['unreachable'],
                "skipped": t['skipped'],
                "failed": t['failures']
            }

class ANSRunner(object):
    """ 
    This is a General object for parallel execute modules. 
    """

    def __init__(self, resource, redisKey=None, logId=None, *args, **kwargs):
        self.resource = resource
        self.inventory = None
        self.variable_manager = None
        self.loader = None
        self.options = None
        self.passwords = None
        self.callback = None
        self.__initializeData()
        self.results_raw = {}
        self.redisKey = redisKey
        self.logId = logId

    def __initializeData(self):
        """ 初始化ansible """
        Options = namedtuple('Options', ['connection', 'module_path', 'forks', 'timeout', 'remote_user',
                                         'ask_pass', 'private_key_file', 'ssh_common_args', 'ssh_extra_args',
                                         'sftp_extra_args',
                                         'scp_extra_args', 'become', 'become_method', 'become_user', 'ask_value_pass',
                                         'verbosity',
                                         'check', 'listhosts', 'listtasks', 'listtags', 'syntax'])

        self.variable_manager = VariableManager()
        self.loader = DataLoader()
        self.options = Options(connection='smart', module_path=None, forks=100, timeout=10,
                               remote_user='root', ask_pass=False, private_key_file=None, ssh_common_args=None,
                               ssh_extra_args=None,
                               sftp_extra_args=None, scp_extra_args=None, become=None, become_method=None,
                               become_user='root', ask_value_pass=False, verbosity=None, check=False, listhosts=False,
                               listtasks=False, listtags=False, syntax=False)

        self.passwords = dict(sshpass=None, becomepass=None)
        self.inventory = MyInventory(self.resource, self.loader, self.variable_manager).inventory
        self.variable_manager.set_inventory(self.inventory)

    def run_model(self, host_list, module_name, module_args):
        """ 
        run module from andible ad-hoc. 
        module_name: ansible module_name 
        module_args: ansible module args 
        """
        play_source = dict(
            name="Ansible Play",
            hosts=host_list,
            gather_facts='no',
            tasks=[dict(action=dict(module=module_name, args=module_args))]
        )
        play = Play().load(play_source, variable_manager=self.variable_manager, loader=self.loader)
        tqm = None
        self.callback = ModelResultsCollector()
        try:
            tqm = TaskQueueManager(
                inventory=self.inventory,
                variable_manager=self.variable_manager,
                loader=self.loader,
                options=self.options,
                passwords=self.passwords,
            )
            tqm._stdout_callback = self.callback
            tqm.run(play)
        finally:
            if tqm is not None:
                tqm.cleanup()

    def run_playbook(self, playbook_path, extra_vars=None):
        """ 
        run ansible palybook 
        """
        try:
            self.callback = PlayBookResultsCollector()
            if extra_vars: self.variable_manager.extra_vars = extra_vars
            executor = PlaybookExecutor(
                playbooks=[playbook_path], inventory=self.inventory, variable_manager=self.variable_manager,
                loader=self.loader,
                options=self.options, passwords=self.passwords,
            )
            executor._tqm._stdout_callback = self.callback
            executor.run()
        except Exception as e:
            return False

    def get_model_result(self):
        self.results_raw = {'success': {}, 'failed': {}, 'unreachable': {}}
        for host, result in self.callback.host_ok.items():
            self.results_raw['success'][host] = result._result

        for host, result in self.callback.host_failed.items():
            self.results_raw['failed'][host] = result._result

        for host, result in self.callback.host_unreachable.items():
            self.results_raw['unreachable'][host] = result._result

        return json.dumps(self.results_raw)

    def get_playbook_result(self):
        self.results_raw = {'skipped': {}, 'failed': {}, 'ok': {}, "status": {}, 'unreachable': {}}

        for host, result in self.callback.task_ok.items():
            self.results_raw['ok'][host] = result._result

        for host, result in self.callback.task_failed.items():
            self.results_raw['failed'][host] = result._result

        for host, result in self.callback.task_status.items():
            self.results_raw['status'][host] = result

        for host, result in self.callback.task_skipped.items():
            self.results_raw['skipped'][host] = result._result

        for host, result in self.callback.task_unreachable.items():
            self.results_raw['unreachable'][host] = result._result
        return self.results_raw

    def handle_cmdb_data(self, data):
        '''处理setup返回结果方法'''
        data_list = []
        for k, v in json.loads(data).items():
            if k == "success":
                for x, y in v.items():
                    cmdb_data = {}
                    data = y.get('ansible_facts')
                    disk_size = 0
                    cpu = data['ansible_processor'][-1]
                    for k, v in data['ansible_devices'].items():
                        if k[0:2] in ['sd', 'hd', 'ss', 'vd']:
                            disk = int((int(v.get('sectors')) * int(v.get('sectorsize'))) / 1024 / 1024 / 1024)
                            disk_size = disk_size + disk
                    cmdb_data['serial'] = data['ansible_product_serial'].split()[0]
                    cmdb_data['ip'] = x
                    cmdb_data['cpu'] = cpu.replace('@', '')
                    ram_total = str(data['ansible_memtotal_mb'])
                    if len(ram_total) == 4:
                        ram_total = ram_total[0] + 'GB'
                    elif len(ram_total) == 5:
                        ram_total = ram_total[0:2] + 'GB'
                    elif len(ram_total) > 5:
                        ram_total = ram_total[0:3] + 'GB'
                    else:
                        ram_total = ram_total + 'MB'
                    cmdb_data['ram_total'] = ram_total
                    cmdb_data['disk_total'] = str(disk_size) + 'GB'
                    cmdb_data['system'] = data['ansible_distribution'] + ' ' + data[
                        'ansible_distribution_version'] + ' ' + data['ansible_userspace_bits']
                    cmdb_data['model'] = data['ansible_product_name'].split(':')[0]
                    cmdb_data['cpu_number'] = data['ansible_processor_count']
                    cmdb_data['vcpu_number'] = data['ansible_processor_vcpus']
                    cmdb_data['cpu_core'] = data['ansible_processor_cores']
                    cmdb_data['hostname'] = data['ansible_hostname']
                    cmdb_data['kernel'] = str(data['ansible_kernel'])
                    cmdb_data['manufacturer'] = data['ansible_system_vendor']
                    if data['ansible_selinux']:
                        cmdb_data['selinux'] = data['ansible_selinux'].get('status')
                    else:
                        cmdb_data['selinux'] = 'disabled'
                    cmdb_data['swap'] = str(data['ansible_swaptotal_mb']) + 'MB'
                    cmdb_data['status'] = 0
                    data_list.append(cmdb_data)
            elif k == "unreachable":
                for x, y in v.items():
                    cmdb_data = {}
                    cmdb_data['status'] = 1
                    cmdb_data['ip'] = x
                    data_list.append(cmdb_data)
        if data_list:
            return data_list
        else:
            return False

    def handle_cmdb_crawHw_data(self, data):
        data_list = []
        for k, v in json.loads(data).items():
            if k == "success":
                for x, y in v.items():
                    cmdb_data = {}
                    cmdb_data['ip'] = x
                    data = y.get('ansible_facts')
                    cmdb_data['mem_info'] = data.get('ansible_mem_detailed_info')
                    cmdb_data['disk_info'] = data.get('ansible_disk_detailed_info')
                    data_list.append(cmdb_data)
        if data_list:
            return data_list
        else:
            return False


### multiprocess pool
# import urllib2 ,requests
# from multiprocessing.dummy import Pool as ThreadPool
# urls = [
#     'http://www.python.org',
#     'http://www.python.org/about/',
#     'http://www.onlamp.com/pub/a/python/2003/04/17/metaclasses.html',
#     'http://www.python.org/doc/',
#     'http://www.python.org/download/',
#     'http://www.python.org/getit/',
#     'http://www.python.org/community/',
#     'https://wiki.python.org/moin/',
#     'http://planet.python.org/',
#     'https://wiki.python.org/moin/LocalUserGroups',
#     'http://www.python.org/psf/',
#     'http://docs.python.org/devguide/',
#     'http://www.python.org/community/awards/'
#     # etc..
#     ]
#
# def get_url(url):
#     result=requests.get(url=url)
#     return result.status_code
# # Make the Pool of workers
# pool = ThreadPool(10)
# # Open the urls in their own threads
# # and return the results
# results = pool.map(get_url, urls)
#
# #close the pool and wait for the work to finish
# pool.close()
# pool.join()
# for m in results:
#     print m
#
# if __name__ == '__main__':
#     resource = [
#         {"hostname": "10.120.180.1"},
#         {"hostname": "10.120.180.2"},
#         {"hostname": "10.120.180.3"},
#     ]
#     #     resource =  {
#     #                     "dynamic_host": {
#     #                         "hosts": [
#     #                                     {"hostname": "192.168.1.34", "port": "22", "username": "root", "password": "jinzhuan2015"},
#     #                                     {"hostname": "192.168.1.130", "port": "22", "username": "root", "password": "jinzhuan2015"}
#     #                                   ],
#     #                         "vars": {
#     #                                  "var1":"ansible",
#     #                                  "var2":"saltstack"
#     #                                  }
#     #                     }
#     #                 }
#
#     rbt = ANSRunner(resource)
# #    rbt.run_model(host_list=["10.120.180.1", "10.120.180.2","10.120.180.3"], module_name='setup',module_args="")
# #    data = rbt.get_model_result()
# #    print json.loads(data).keys()
# #    print data
#     #     print rbt.handle_model_data(data, 'synchronize', module_args='src=/data/webserver/VManagePlatform/ dest=/data/webserver/VManagePlatform/ compress=yes delete=yes recursive = yes')
# # rbt.run_model(host_list=["192.168.1.34","192.168.1.130","192.168.1.1"],module_name='ping',module_args="")
#     rbt.run_playbook(playbook_path='/opt/app/ansible/t.yml',extra_vars={"host":["10.120.180.1","10.120.180.2"],"name":"new_one"})
#     data = rbt.get_playbook_result()
#     for m in data.keys():
#         if data.get(m):
#             print '\n'+m+':\n'
#             print data.get(m)
# #     print rbt.handle_playbook_data_to_html(data)
# # print rbt.handle_model_data(module_name='copy',module_args="src=/root/git.log dest=/tmp/test.txt",data=data)
