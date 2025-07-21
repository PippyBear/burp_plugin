# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IScanIssue
from java.net import URL
import hashlib

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = callbacks.getStdout()

        callbacks.setExtensionName("XFF/IP Bypass Passive Detector by pippybear")
        callbacks.registerHttpListener(self)
        print("[+] XFF/IP header bypass detector loaded by pippybear")

        # 伪造 IP 头列表
        self.spoof_headers = {
            "Client-IP": "127.0.0.1",
            "X-Real-Ip": "127.0.0.1",
            "Redirect": "127.0.0.1",
            "Referer": "http://127.0.0.1",
            "X-Client-IP": "127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "X-Forwarded-By": "127.0.0.1",
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded-Host": "127.0.0.1",
            "X-Forwarded-Port": "80",
            "X-True-IP": "127.0.0.1",
        }
        self.tested_requests = set()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag != self.callbacks.TOOL_REPEATER or messageIsRequest:
            return

        service = messageInfo.getHttpService()
        orig_req = messageInfo.getRequest()
        orig_resp = messageInfo.getResponse()

        if not orig_resp:
            return

        req_info = self.helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
        body = orig_req[req_info.getBodyOffset():]
        orig_headers = req_info.getHeaders()
        orig_resp_info = self.helpers.analyzeResponse(orig_resp)
        orig_status = orig_resp_info.getStatusCode()
        orig_length = len(orig_resp)

        url = req_info.getUrl().toString()
        body_hash = hashlib.sha256(body).hexdigest()

        for header, value in self.spoof_headers.items():
            unique_key = "{}#{}#{}".format(url, header.lower(), body_hash)
            if unique_key in self.tested_requests:
                continue  # 跳过已测试
            self.tested_requests.add(unique_key)

            # 构造新的 header 列表
            new_headers = list(orig_headers)
            # 替换或添加 header
            replaced = False
            for i in range(len(new_headers)):
                if new_headers[i].lower().startswith(header.lower() + ":"):
                    new_headers[i] = "{}: {}".format(header, value)
                    replaced = True
            if not replaced:
                new_headers.append("{}: {}".format(header, value))

            new_req = self.helpers.buildHttpMessage(new_headers, body)
            new_resp_obj = self.callbacks.makeHttpRequest(service, new_req)
            new_resp = new_resp_obj.getResponse()
            if not new_resp:
                continue

            new_resp_info = self.helpers.analyzeResponse(new_resp)
            new_status = new_resp_info.getStatusCode()
            new_length = len(new_resp)

            # 简单判断差异：状态码不同 或 响应长度变化大于100
            if new_status != orig_status or abs(new_length - orig_length) > 100:
                url = self.helpers.analyzeRequest(service, orig_req).getUrl()
                issue = CustomScanIssue(
                    httpService=service,
                    url=url,
                    httpMessages=[messageInfo, new_resp_obj],  # ✅ 包含原始请求+伪造请求
                    name="[!] Possible IP Bypass via <b>{}</b>".format(header),
                    detail="""
                        <b>IP bypass check triggered.</b><br>
                        Injected header: <code>{}: {}</code><br>
                        Status: <b>{} → {}</b><br>
                        Length: <b>{} → {}</b><br>
                        Check both requests in the Request/Response panel for comparison.
                        """.format(header, value, orig_status, new_status, orig_length, new_length),
                    severity="Medium"
                )
                self.callbacks.addScanIssue(issue)
                print("[!] Bypass alert: {} caused response change at {}".format(header, url))

# 漏洞报告结构
class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self): return self._url
    def getIssueName(self): return self._name
    def getIssueType(self): return 0
    def getSeverity(self): return self._severity
    def getConfidence(self): return "Firm"
    def getIssueBackground(self): return "Detects possible IP-based access control bypass using spoofed headers."
    def getRemediationBackground(self): return "Ensure access control is based on trusted source IP only (e.g. remoteAddr) and not spoofable headers."
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return self._httpMessages
    def getHttpService(self): return self._httpService
