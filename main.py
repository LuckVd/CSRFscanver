import random
import re
import time
from urllib.parse import urlparse

import requests

from utils import getUrl, getParams, strength

headers = {  # default headers
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip,deflate',
    'Connection': 'close',
    'DNT': '1',
    'Upgrade-Insecure-Requests': '1',
}
commonNames = ['csrf', 'auth', 'token', 'verify', 'hash']


def requester(url, data, headers, GET, delay):
    time.sleep(delay)
    user_agents = ['Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36'
                   'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991']
    if headers:
        if 'User-Agent' not in headers:
            headers['User-Agent'] = random.choice(user_agents)
    if GET:
        response = requests.get(
            url, params=data, headers=headers, verify=False)
    else:
        response = requests.post(url, data=data, headers=headers, verify=False)
    return response

def zetanize(url, response):
    parsedUrl = urlparse(url)
    mainUrl = parsedUrl.scheme + '://' + parsedUrl.netloc

    def e(string):
        return string.encode('utf-8')

    def d(string):
        return string.decode('utf-8')

    response = re.sub(r'(?s)<!--.*?-->', '', response)
    forms = {}
    matches = re.findall(r'(?i)(?s)<form.*?</form.*?>', response)
    num = 0
    for match in matches:
        page = re.search(r'(?i)action=[\'"](.*?)[\'"]', match)
        method = re.search(r'(?i)method=[\'"](.*?)[\'"]', match)
        forms[num] = {}
        action = d(e(page.group(1)))
        if not action.startswith('http'):
            if action.startswith('/'):
                action = mainUrl + action
            else:
                action = mainUrl + '/' + action
        forms[num]['action'] = action.replace('&amp;', '&') if page else ''
        forms[num]['method'] = d(
            e(method.group(1)).lower()) if method else 'get'
        forms[num]['inputs'] = []
        inputs = re.findall(r'(?i)(?s)<input.*?>', response)
        for inp in inputs:
            inpName = re.search(r'(?i)name=[\'"](.*?)[\'"]', inp)
            if inpName:
                inpType = re.search(r'(?i)type=[\'"](.*?)[\'"]', inp)
                inpValue = re.search(r'(?i)value=[\'"](.*?)[\'"]', inp)
                inpName = d(e(inpName.group(1)))
                inpType = d(e(inpType.group(1)))if inpType else ''
                inpValue = d(e(inpValue.group(1))) if inpValue else ''
                if inpType.lower() == 'submit' and inpValue == '':
                    inpValue = 'Submit Query'
                inpDict = {
                    'name': inpName,
                    'type': inpType,
                    'value': inpValue
                }
                forms[num]['inputs'].append(inpDict)
        num += 1
    return forms

def evaluate(url,dataset, weakTokens, tokenDatabase, allTokens, insecureForms):
    done = []
    for i in dataset:
        localTokens = set()
        for each in i.values():
            protected = False
            action = each['action']
            method = each['method']
            inputs = each['inputs']
            for inp in inputs:
                name = inp['name']
                value = inp['value']
                if value and re.match(r'^[\w\-_]+$', value):
                    if strength(value) > 10:
                        localTokens.add(value)
                        protected = True
                        break
                    else:
                        for name in commonNames:
                            if name in name.lower():
                                weakTokens.append({url: {name: value}})
            if not protected and action not in done:
                done.append(action)
                insecureForms.append({url: each})
        for token in localTokens:
            allTokens.append(token)
        tokenDatabase.append({url: localTokens})

def scan(oriurl:str):
    forms=list()
    params = getParams(oriurl, '', True)
    url = getUrl(oriurl, '', True)
    response = requester(url, params, headers, True, 0).text
    forms.append(zetanize(url, response))
    print(forms)
    allTokens = []
    weakTokens = []
    tokenDatabase = []
    insecureForms = []

    evaluate(url,forms, weakTokens, tokenDatabase, allTokens, insecureForms)
    if insecureForms:
        print('%s Insecure form(s) found' )
        for insecureForm in insecureForms:
            url = list(insecureForm.keys())[0]
            action = list(insecureForm.values())[0]['action']
            print(url,action)




scan("http://192.168.144.128/DVWA-master/vulnerabilities/csrf?a=1&b=2")