#encoding=utf8
import time
import re
import urlparse
import urllib
import random
import json

import requests
from PIL import Image
from StringIO import StringIO

def timestamp():
    return int(time.time())


class WX(object):
    def __init__(self):
        self.session = requests.session()
        self.uuid = None
        self.wxuin = None
        self.wxsid = None
        self.deviceid = self._rand_devid()
        self.user = {}
        self.sync_key = []
        self.contacts = []

    def login(self):
        self.getUUID()
        self.showQrCode()
        if self.waitForScan():
            redirect_url = self.waitForLogin()
            self.session.get(redirect_url)
            dcks = requests.utils.dict_from_cookiejar(self.session.cookies)
            self.wxuin = dcks.get('wxuin')
            self.wxsid = dcks.get('wxsid')
        else:
            raise ValueError('login error: 408')

    def wxInit(self):
        url = 'https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxinit?r=%s' % timestamp()
        data = {"BaseRequest":{"Uin":self.wxuin,"Sid":self.wxsid,"Skey":"","DeviceID":self.deviceid}}
        resp = self.session.post(url, json=data)
        ddata = json.loads(resp.content, encoding='utf8')
        self.user = ddata.get('User')
        self.sync_key = ddata.get('SyncKey').get('List')

    def openWxStatusNotify(self):
        pass

    def getContacts(self):
        url = 'https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxgetcontact?r=%s' % timestamp()
        resp = self.session.post(url, json={})
        ddata = json.loads(resp.content, encoding='utf8')
        base_resp = ddata.get('BaseResponse')
        if int(base_resp.get('Ret')) != 0:
            raise ValueError(base_resp.get('ErrMsg'))
        self.contacts = ddata.get('MemberList')

    def syncCheck(self):
        url = '''https://webpush.weixin.qq.com/cgi-bin/mmwebwx-bin/synccheck?\
            callback=jQuery18309326978388708085_{ts}\
            &r={ts}&sid={sid}&uin={uin}&deviceid={deviceid}&synckey={synckey}&_={ts}
            '''.format(
                ts=timestamp(),
                sid=self.wxsid,
                uin=self.wxuin,
                deviceid=self.deviceid,
                synckey=urllib.quote('|'.join(['{}_{}'.format(d.get('Key'), d.get('Val')) for d in self.sync_key]))
            )

        resp = self.session.get(url)
        ret = re.findall('retcode:\"(\d+)\",selector:\"(\d+)\"', resp.content)[0]
        retcode, selector = [int(x) for x in ret]
        if retcode != 0:
            raise ValueError('sync check return error')
        if selector==6:
            self.receiveMsg()

    def receiveMsg(self):
        url = 'https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxsync?sid={}&r={}'.format(self.wxsid, timestamp())
        data = {
            "BaseRequest": {
                "Uin": self.wxuin, "Sid": self.wxsid
            },
            "SyncKey": {
                "Count": len(self.sync_key),
                "List": self.sync_key
            },
            "rr": timestamp()
        }
        resp = self.session.post(url, json=data)
        ddata = json.loads(resp.content, encoding='utf8')
        from pprint import pprint
        pprint(ddata)

    def sendMsg(self, to_username, content):
        url = 'https://wx.qq.com/cgi-bin/mmwebwx-bin/webwxsendmsg?sid=%s&r=%s' % (self.wxsid, timestamp())
        data = {
            "BaseRequest":{
                "DeviceID" : self.deviceid,
                "Sid" : self.wxsid,
                "Skey" : "F820928BBA5D8ECA23448F076D2E8A915E1349E9FB4F4332",
                "Uin" : self.wxuin
            },
            "Msg" : {
                "ClientMsgId" : timestamp(),
                "Content" : content,
                "FromUserName" : self.my_username,
                "LocalID" : timestamp(),
                "ToUserName" : to_username,
                "Type" : 1
            },
            "rr" : timestamp()
        }
        self.session.post(url, json=data)

    def getUUID(self):
        url = 'https://login.weixin.qq.com/jslogin?appid=wx782c26e4c19acffb&fun=new&lang=zh_CN&_=%s' % (timestamp())
        resp = self.session.get(url)
        code = re.findall('\d+', resp.content)[0]
        if code != '200':
            raise ValueError('get uuid error')
        uu_id = re.findall('\"([^\"]+)\"', resp.content)[0]
        self.uuid = uu_id

    def showQrCode(self):
        assert self.uuid
        url = 'https://login.weixin.qq.com/qrcode/%s?t=webwx' % self.uuid
        resp = self.session.get(url)
        im = Image.open(StringIO(resp.content))
        im.show()

    def waitForScan(self):
        return self._scan(1)

    def waitForLogin(self):
        return self._scan(0)

    @property
    def my_username(self):
        return self.user

    #tip : 1:未扫描 0:已扫描
    def _scan(self, tip=1):
        assert self.uuid
        url = 'https://login.wx.qq.com/cgi-bin/mmwebwx-bin/login'
        payload = {
            'tip' : str(tip),
            '_' : str(timestamp()),
            'uuid' : self.uuid,
            'loginicon' : 'true',
        }
        resp = self.session.get(url+'?'+urllib.urlencode(payload))
        code = re.findall('window.code=(\d+)', resp.content)[0]
        if code == '201':
            return True
        elif code == '200':
            redirect_url = re.findall('window.redirect_uri=\"([^\"]+)\"', resp.content)[0]
            return redirect_url
        return False

    def _parse_qs(self, url):
        d = urlparse.parse_qs(urlparse.urlparse(url).query)
        results = {}
        for k, v in d.items():
            if isinstance(v, list) and len(v)==1:
                v = v[0]
            results[k] = v
        return results

    def _rand_devid(self):
        return 'e'+''.join([random.choice('0123456789') for _ in range(10)])


wx = WX()
wx.login()
wx.wxInit()
wx.getContacts()
wx.syncCheck()


print  'done'
