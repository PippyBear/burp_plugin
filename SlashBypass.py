# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IScanIssue
from java.io import PrintWriter
from java.util.concurrent import ThreadPoolExecutor, LinkedBlockingQueue, TimeUnit
import difflib
import threading
import collections

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity="Medium", confidence="Tentative"):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x08000000  # 自定义类型

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService


class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("URI Slash Bypass Detector By PippyBear")
        callbacks.registerHttpListener(self)

        # 有界线程池，最大5线程，队列容量100
        self._executor = ThreadPoolExecutor(
            5, 5, 60, TimeUnit.SECONDS,
            LinkedBlockingQueue(100)
        )

        # 定义黑名单 Host，检测时跳过这些域名
        self._blocked_hosts = [
            "*.google.com",
            "*.gvt2.com",
            "*.facebook.net",
            "*.googletagmanager.com",
            "*.doubleclick.net"
        ]

        # 线程安全的LRU缓存，最大1000条路径，防止重复检测
        self._lock = threading.Lock()
        self._tested_paths = collections.OrderedDict()
        self._max_cache_size = 1000

        self._stdout.println("[+] URI Slash Bypass Detector By PippyBear")

    def _move_to_end(self, d, key):
        # 兼容 Jython，手动实现 move_to_end，将已检测路径移到末尾（最新）
        value = d.pop(key)
        d[key] = value
        return d

    def host_in_blacklist(self, host):
        host = host.lower()
        for pattern in self._blocked_hosts:
            pattern = pattern.lower()
            if pattern.startswith("*."):
                if host == pattern[2:] or host.endswith("." + pattern[2:]):
                    return True
            else:
                if host == pattern:
                    return True
        return False

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag != self._callbacks.TOOL_REPEATER or messageIsRequest:
            return

        analyzedRequest = self._helpers.analyzeRequest(messageInfo)
        headers = analyzedRequest.getHeaders()
        host = analyzedRequest.getUrl().getHost()
        path = analyzedRequest.getUrl().getPath()

        # 如果请求 Host 在黑名单中，跳过检测
        if self.host_in_blacklist(host):
            self._stdout.println("[*] Skipping path {} for blocked host {}".format(path, host))
            return

        # 跳过自己插件发的请求（标记头）
        for header in headers:
            if header.startswith("X-Bypass-Checker:"):
                return

        # 过滤静态资源，减少无效检测
        if any(path.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".svg"]):
            return

        with self._lock:
            if path in self._tested_paths:
                # 路径已经检测过，更新缓存顺序，跳过
                self._tested_paths = self._move_to_end(self._tested_paths, path)
                self._stdout.println("[*] Skipping already tested path: {}".format(path))
                return
            else:
                self._tested_paths[path] = True
                # 超出缓存大小，删除最旧记录
                if len(self._tested_paths) > self._max_cache_size:
                    removed = self._tested_paths.popitem(last=False)
                    self._stdout.println("[*] Evicted oldest cached path: {}".format(removed[0]))

        # 异步提交检测任务
        try:
            self._stdout.println("[*] Submitting async check for path: {}".format(path))
            threading.Thread(target=self.check_slash_bypass, args=(messageInfo,)).start()
        except Exception as e:
            self._stderr.println("[!] Task submission rejected or failed: {}".format(e))

    def check_slash_bypass(self, messageInfo):
        self._stdout.println("[*] >>> Entered check_slash_bypass <<<")
        try:
            analyzedRequest = self._helpers.analyzeRequest(messageInfo)
            headers = list(analyzedRequest.getHeaders())
            body = messageInfo.getRequest()[analyzedRequest.getBodyOffset():]
            method, path, protocol = headers[0].split(" ", 2)

            self._stdout.println("[*] Original request line: {} {} {}".format(method, path, protocol))

            # 先主动发送原始请求，拿响应
            http_service = messageInfo.getHttpService()
            orig_resp_info = self._callbacks.makeHttpRequest(http_service, messageInfo.getRequest())

            orig_resp = orig_resp_info.getResponse()
            if orig_resp is None:
                self._stdout.println("[!] Failed to get original response, skipping check")
                return

            # 编码 URI 中的 /（首个 / 保持不变）
            if path.startswith("/"):
                encoded_path = "/" + path[1:].replace("/", "%2F")
            else:
                encoded_path = path.replace("/", "%2F")

            self._stdout.println("[*] Encoded path: {}".format(encoded_path))

            encoded_headers = list(headers)
            encoded_headers.append("X-Bypass-Checker: 1") 
            encoded_headers[0] = "{} {} {}".format(method, encoded_path, protocol)
            encoded_request = self._helpers.buildHttpMessage(encoded_headers, body)

            encoded_resp_info = self._callbacks.makeHttpRequest(http_service, encoded_request)
            new_resp = encoded_resp_info.getResponse()



            self._stdout.println("[*] orig_resp: {}".format(orig_resp))
            self._stdout.println("[*] new_resp: {}".format(new_resp))

            if new_resp is None:
                self._stdout.println("[!] Encoded response is None, skipping check")
                return

            orig_analyzed = self._helpers.analyzeResponse(orig_resp)
            new_analyzed = self._helpers.analyzeResponse(new_resp)

            orig_body = orig_resp[orig_analyzed.getBodyOffset():]
            new_body = new_resp[new_analyzed.getBodyOffset():]

            orig_status = orig_analyzed.getStatusCode()
            new_status = new_analyzed.getStatusCode()

            # 如果新的响应是 4XX，直接退出（例如 403、404、401、400 等）
            if 400 <= new_status < 500:
                self._stdout.println("[*] Skipping check due to new response being 4XX: {}".format(new_status))
                return

            orig_len = len(orig_body)
            new_len = len(new_body)

            self._stdout.println("[*] Original status: {}, length: {}".format(orig_status, orig_len))
            self._stdout.println("[*] Encoded status: {}, length: {}".format(new_status, new_len))

            sm = difflib.SequenceMatcher(None, orig_body.tostring(), new_body.tostring())
            similarity = sm.ratio()

            self._stdout.println("[*] Body similarity ratio: {:.2f}".format(similarity))

            # 判断是否可能存在绕过
            if orig_status != new_status or abs(orig_len - new_len) > 50 or similarity < 0.85:
                self._stdout.println("=== start Potential URI Bypass Detected ===")
                orig_url = analyzedRequest.getUrl()
                enc_url = self._helpers.analyzeRequest(encoded_resp_info).getUrl()

                self._stdout.println("=== Potential URI Bypass Detected ===")
                self._stdout.println("Original URL : {}".format(orig_url))
                self._stdout.println("Encoded URL  : {}".format(enc_url))
                self._stdout.println("Original Status: {}, Length: {}".format(orig_status, orig_len))
                self._stdout.println("Encoded  Status: {}, Length: {}".format(new_status, new_len))
                self._stdout.println("Body Similarity: {:.2f}".format(similarity))
                self._stdout.println("=====================================")

                # 构造 Issue 详情并上报（你也可以注释掉以下部分以避免上报）
                detail = (
                    "Original URL: {}<br>"
                    "Encoded URL: {}<br>"
                    "Original Status: {}, Length: {}<br>"
                    "Encoded Status: {}, Length: {}<br>"
                    "Body Similarity: {:.2f}<br>"
                    "<br>"
                    "This indicates a potential URI Slash Bypass vulnerability."
                ).format(orig_url, enc_url, orig_status, orig_len, new_status, new_len, similarity)

                issue = CustomScanIssue(
                    http_service,
                    orig_url,
                    [messageInfo, encoded_resp_info],
                    "Potential URI Slash Bypass",
                    detail,
                    severity="Medium",
                    confidence="Tentative"
                )

                self._callbacks.addScanIssue(issue)
            else:
                self._stdout.println("[*] No significant difference detected for path: {}".format(path))

        except Exception as e:
            self._stderr.println("[!] Error in async check: {}".format(e))
