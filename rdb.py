import requests
import httplib,json
header={"Content-Type": "application/json"}

def get(url):
    conn=requests.get(url,headers=header)
    return conn.json()

def check_redis(group_url):
    url="{0}/api/server_groups".format(group_url)
    result=get(url)
    print result
    for m in result:
        for n in m.get('servers'):
            check_url=None
            check_result=None
            check_url="{0}/api/redis/{1}/stat?group_id={2}&type={3}".format(group_url,n.get('addr'),n.get('group_id'),n.get('type'))
            check_result=get(check_url)
            print check_url
            print check_result
            print "{0}/{1}".format(check_result.get('used_memory'),check_result.get('maxmemory'))

all_groups=[
    "http://10.0.8.228:29939"
]
for m in all_groups:
    check_redis(m)
# # http://10.0.8.229:29938/api/redis/10.0.8.144:9938/stat?group_id=1&type=master
# 10.0.8.228:29939
# 10.0.8.228:29904
# 10.0.8.228:29931
# 10.0.8.228:29932
# 10.0.8.228:29933
# 10.0.8.228:29934
# 10.0.8.228:29935
# 10.0.8.228:29936
# 10.0.8.228:29937
# 10.0.8.229:29927
# 10.0.8.229:29929
# 10.0.8.229:29930
# 10.0.8.229:29938
# 10.0.8.229:29928