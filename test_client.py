import requests

appHost = '127.0.0.1'
appPort = 8001
appPath = '/weber/1234/IA24GRS3/15'
cookies = { 'weber-auth':'ir38498' }

proxyHost = '127.0.0.1'
proxyPort = 8000
url = 'http://' + proxyHost + ":" + str(proxyPort) + appPath

r = requests.get(url,cookies=cookies)
