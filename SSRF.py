# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IParameter
from burp import IBurpExtenderCallbacks
from javax.swing import (
    JPanel, JButton, JLabel, JScrollPane, JTable,
    BoxLayout, JMenuItem, JPopupMenu, JOptionPane,
    JList, DefaultListModel
)
from javax.swing.table import DefaultTableCellRenderer
from java.awt import Color
from java.awt import FlowLayout
from javax.swing.table import AbstractTableModel
from java.util import ArrayList
from java.awt import Dimension
from threading import Thread
from javax.swing import SwingUtilities
from java.awt.event import MouseAdapter
from javax.swing import JCheckBox
import json
import re
import time


class TableMouseListener(MouseAdapter):
    def __init__(self, popup):
        self.popup = popup

    def mousePressed(self, event):
        if event.isPopupTrigger():
            self.popup.show(event.getComponent(), event.getX(), event.getY())

    def mouseReleased(self, event):
        if event.isPopupTrigger():
            self.popup.show(event.getComponent(), event.getX(), event.getY())

class StatusColorRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = super(StatusColorRenderer, self).getTableCellRendererComponent(
            table, value, isSelected, hasFocus, row, col
        )

        if isSelected:
            return c   # 让系统处理选中颜色

        status = table.getValueAt(row, 3)

        if status == "Triggered":
            c.setBackground(Color(255, 200, 200))
        elif status == "Not Triggered":
            c.setBackground(Color(220, 220, 220))
        elif status == "Reflected":
            c.setBackground(Color(255, 230, 200))
        else:
            c.setBackground(Color.white)

        return c

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.collaborator = callbacks.createBurpCollaboratorClientContext()

        self.callbacks.setExtensionName("SSRF Detector")
        self.callbacks.registerHttpListener(self)
        self.callbacks.registerContextMenuFactory(self)

        self.collab_mapping = {}
        self.start_times = {}

        self.table_data = []
        self.row_map = {}

        # ===== 新增 =====
        self.whitelist_hosts = set()
        self.seen_proxy_requests = set()
        self.whitelist_model = DefaultListModel()
        self.proxy_enabled = True

        self.initUI()
        callbacks.addSuiteTab(self)

        self.keep_checking = True
        t = Thread(target=self.autoCheckCollaborator)
        t.setDaemon(True)
        t.start()

    # ================= UI =================

    def initUI(self):
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))

        # ===== Title =====
        self.label = JLabel("SSRF Detection Results")
        self.panel.add(self.label)

        # ===== Result Table =====
        self.table_model = SimpleTableModel(
            self.table_data,
            ["Request URL", "Collaborator Payload", "Interaction Type", "Status"]
        )
        self.table = JTable(self.table_model)
        self.table.setPreferredScrollableViewportSize(Dimension(750, 260))
        self.panel.add(JScrollPane(self.table))

        # ===== Toolbar =====
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT))

        self.proxyCheckbox = JCheckBox(
            "Enable Proxy Auto Detect",
            True,
            actionPerformed=lambda e: self.toggleProxy()
        )
        toolbar.add(self.proxyCheckbox)

        self.refreshButton = JButton("Check Collaborator", actionPerformed=self.checkCollaborator)
        self.clearButton = JButton("Clear Records", actionPerformed=lambda e: self.clearRecords())
        self.addWhitelistBtn = JButton("Add Whitelist", actionPerformed=lambda e: self.addWhitelist())
        self.removeWhitelistBtn = JButton("Remove Whitelist", actionPerformed=lambda e: self.removeWhitelist())

        toolbar.add(self.refreshButton)
        toolbar.add(self.clearButton)
        toolbar.add(self.addWhitelistBtn)
        toolbar.add(self.removeWhitelistBtn)

        self.panel.add(toolbar)

        # ===== Whitelist Board =====
        wl_label = JLabel("Whitelist Hosts:")
        self.panel.add(wl_label)

        self.whitelist_list = JList(self.whitelist_model)
        self.whitelist_list.setVisibleRowCount(4)
        self.panel.add(JScrollPane(self.whitelist_list))

        # ===== Table Right Click =====
        self.popup = JPopupMenu()
        self.popup.add(JMenuItem("Clear Records", actionPerformed=lambda e: self.clearRecords()))
        self.table.addMouseListener(TableMouseListener(self.popup))
        renderer = StatusColorRenderer()
        for i in range(self.table.getColumnCount()):
            self.table.getColumnModel().getColumn(i).setCellRenderer(renderer)


    def toggleProxy(self):
        self.proxy_enabled = self.proxyCheckbox.isSelected()
        print("[SSRFDetector] Proxy auto detect:",
              "ON" if self.proxy_enabled else "OFF")

    def getTabCaption(self):
        return "SSRF Detector"

    def getUiComponent(self):
        return self.panel

    # ================= 白名单 =================

    def addWhitelist(self):
        host = JOptionPane.showInputDialog(
            self.panel,
            "Enter host/domain to whitelist (e.g. example.com):"
        )
        if host:
            h = host.strip().lower()
            if h not in self.whitelist_hosts:
                self.whitelist_hosts.add(h)
                self.whitelist_model.addElement(h)
                print("[SSRFDetector] Added whitelist:", h)

    def removeWhitelist(self):
        idx = self.whitelist_list.getSelectedIndex()
        if idx >= 0:
            host = self.whitelist_model.getElementAt(idx)
            self.whitelist_hosts.discard(host)
            self.whitelist_model.remove(idx)
            print("[SSRFDetector] Removed whitelist:", host)


    def isWhitelisted(self, analyzed):
        try:
            # 1️⃣ 优先从 Host header 取（Proxy 下最可靠）
            for h in analyzed.getHeaders():
                if h.lower().startswith("host:"):
                    host = h.split(":", 1)[1].strip().lower()
                    break
            else:
                # 2️⃣ 兜底：从 URL 取
                url = analyzed.getUrl()
                if not url:
                    return False
                host = url.getHost().lower()

            for w in self.whitelist_hosts:
                if host == w or host.endswith("." + w):
                    return True
        except:
            pass

        return False

    # ================= Context Menu =================

    def createMenuItems(self, invocation):
        menu = ArrayList()
        messages = invocation.getSelectedMessages()
        if messages:
            menu.add(JMenuItem(
                "Send to SSRF Detector",
                actionPerformed=lambda e: self.processRequest(messages[0])
            ))
        return menu

    # ================= Proxy 自动识别 =================

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.proxy_enabled:
            return
        if toolFlag != IBurpExtenderCallbacks.TOOL_PROXY:
            return
        if not messageIsRequest:
            return

        try:
            analyzed = self.helpers.analyzeRequest(messageInfo)

            if self.isWhitelisted(analyzed):
                return

            url = analyzed.getUrl()
            url_str = url.toString() if url else ""

            req_key = analyzed.getMethod() + " " + url_str
            if req_key in self.seen_proxy_requests:
                return
            self.seen_proxy_requests.add(req_key)

            ssrf_params = ["url", "redirect", "target", "next", "returnurl", "callback"]

            for p in analyzed.getParameters():
                if p.getName().lower() in ssrf_params:
                    print("[SSRFDetector] Auto trigger from Proxy:", analyzed.getUrl())
                    self.processRequest(messageInfo)
                    break

        except Exception as e:
            print("[SSRFDetector] Proxy auto detect error:", e)

    # ================= 核心 SSRF 逻辑（原样） =================

    def is_ssrf_successful(self, response_text):
        return bool(re.search(r"<body>\s*([a-zA-Z0-9]{20,40})\s*</body>", response_text))

    def processRequest(self, message):
        def run():
            try:
                request = message.getRequest()
                analyzed = self.helpers.analyzeRequest(message)
                url = analyzed.getUrl()

                collab_id = self.collaborator.generatePayload(True)
                collab_url = "http://" + collab_id

                self.collab_mapping[collab_url] = url.toString() if url else "N/A"
                self.start_times[collab_url] = time.time()

                self.updateOrAddRow([
                    url.toString() if url else "N/A",
                    collab_url,
                    "Waiting",
                    "Waiting"
                ])

                # ===== 判断是否 JSON（必须在 updateParameter 之前）=====
                headers = analyzed.getHeaders()
                is_json = any("application/json" in h.lower() for h in headers)

                param_names = ["url", "redirect", "target", "next", "returnurl", "callback"]
                new_request = request

                # ===== 非 JSON：才允许 updateParameter =====
                if not is_json:
                    for p in analyzed.getParameters():
                        if p.getName().lower() in param_names:
                            new_param = self.helpers.buildParameter(
                                p.getName(), collab_url, p.getType()
                            )
                            new_request = self.helpers.updateParameter(new_request, new_param)

                # ===== 重新解析 request =====
                analyzed_new = self.helpers.analyzeRequest(new_request)
                headers = analyzed_new.getHeaders()
                body = new_request[analyzed_new.getBodyOffset():]
                body_str = self.helpers.bytesToString(body)

                print("[DEBUG body before inject]", repr(body_str))

                # ===== JSON / Form body 注入 =====
                new_body = self.injectPayload(body_str, collab_url, is_json)
                new_request = self.helpers.buildHttpMessage(headers, new_body)

                response = self.callbacks.makeHttpRequest(
                    message.getHttpService(), new_request
                )

                resp = response.getResponse()
                resp_info = self.helpers.analyzeResponse(resp)
                resp_body = resp[resp_info.getBodyOffset():]
                resp_str = self.helpers.bytesToString(resp_body)

                if self.is_ssrf_successful(resp_str):
                    self.updateOrAddRow([
                        url.toString() if url else "N/A",
                        collab_url,
                        "Reflected",
                        "Triggered"
                    ])

            except Exception as e:
                print("[SSRFDetector] processRequest error:", e)

        Thread(target=run).start()


    def deepInjectJson(self, obj, payload):
        ssrf_keys = ["url", "redirect", "target", "next", "returnurl", "callback"]

        if isinstance(obj, dict):
            for k in obj:
                v = obj[k]
                if k.lower() in ssrf_keys and isinstance(v, str):
                    obj[k] = payload
                else:
                    self.deepInjectJson(v, payload)

        elif isinstance(obj, list):
            for i in range(len(obj)):
                self.deepInjectJson(obj[i], payload)

    def injectPayload(self, body, payload, is_json):
        body_str = body or ""

        # 1️⃣ 表单 / query
        for k in ["url", "redirect", "target", "next", "returnurl", "callback"]:
            body_str = re.sub(
                r'(?i)("?' + k + r'"?\s*:\s*)"[^"]*"',
                r'\1"' + payload + '"',
                body_str
            )
            body_str = re.sub(
                r'(?i)(' + k + r')=([^&]+)',
                r'\1=' + payload,
                body_str
            )

        # 2️⃣ JSON 深层
        if is_json:
            try:
                j = json.loads(body_str)
                self.deepInjectJson(j, payload)
                body_str = json.dumps(j)
            except Exception as e:
                print("[SSRFDetector] JSON inject error:", e)

        return self.helpers.stringToBytes(body_str)

    # ================= Collaborator 检查 =================

    def checkCollaborator(self, event=None):
        self._checkCollaborator()

    def _checkCollaborator(self):
        try:
            now = time.time()
            interactions = self.collaborator.fetchAllCollaboratorInteractions()

            # 1️⃣ 处理已触发
            for data in interactions:
                pid = data.getProperty("interaction_id").lower()
                for k in list(self.collab_mapping.keys()):
                    sub = k.replace("http://", "").split(".")[0].lower()
                    if pid == sub:
                        self.updateOrAddRow([
                            self.collab_mapping[k],
                            k,
                            data.getProperty("protocol"),
                            "Triggered"
                        ])
                        self.collab_mapping.pop(k, None)
                        self.start_times.pop(k, None)

            # 2️⃣ 处理超时未触发
            for k in list(self.start_times.keys()):
                if now - self.start_times[k] > 180:
                    self.updateOrAddRow([
                        self.collab_mapping.get(k, "N/A"),
                        k,
                        "Timeout",
                        "Not Triggered"
                    ])
                    self.start_times.pop(k, None)
                    self.collab_mapping.pop(k, None)

        except Exception as e:
            print("[SSRFDetector] collaborator error:", e)

    def autoCheckCollaborator(self):
        while self.keep_checking:
            self._checkCollaborator()
            time.sleep(30)

    def updateOrAddRow(self, row):
        def ui():
            payload = row[1]
            new_status = row[3]

            if payload in self.row_map:
                idx = self.row_map[payload]
                old_row = self.table_model.data[idx]
                old_status = old_row[3]

                # ===== 状态防回退 =====
                if old_status == "Triggered":
                    return
                if old_status == "Reflected" and new_status != "Triggered":
                    return
                if old_status == "Not Triggered":
                    return

                self.table_model.data[idx] = row
            else:
                self.row_map[payload] = len(self.table_model.data)
                self.table_model.data.append(row)

            self.table_model.fireTableDataChanged()

        SwingUtilities.invokeLater(ui)

    def clearRecords(self):
        def ui():
            self.table_model.data[:] = []
            self.row_map.clear()
            self.collab_mapping.clear()
            self.start_times.clear()
            self.seen_proxy_requests.clear()
            self.table_model.fireTableDataChanged()

        SwingUtilities.invokeLater(ui)


class SimpleTableModel(AbstractTableModel):
    def __init__(self, data, columns):
        self.data = data
        self.columns = columns

    def getRowCount(self):
        return len(self.data)

    def getColumnCount(self):
        return len(self.columns)

    def getValueAt(self, r, c):
        return self.data[r][c]

    def getColumnName(self, c):
        return self.columns[c]
