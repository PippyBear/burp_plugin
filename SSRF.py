# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IParameter
from burp import IBurpExtenderCallbacks
from javax.swing import (
    JPanel, JButton, JLabel, JScrollPane, JTable,
    BoxLayout, JMenuItem, JPopupMenu, JOptionPane,
    JList, DefaultListModel
)
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

                param_names = ["url", "redirect", "target", "next", "returnurl", "callback"]
                new_request = request

                for p in analyzed.getParameters():
                    if p.getName().lower() in param_names:
                        new_param = self.helpers.buildParameter(
                            p.getName(), collab_url, p.getType()
                        )
                        new_request = self.helpers.updateParameter(new_request, new_param)

                analyzed_new = self.helpers.analyzeRequest(new_request)
                body = new_request[analyzed_new.getBodyOffset():]
                body_str = self.helpers.bytesToString(body)
                headers = analyzed_new.getHeaders()

                new_body = self.injectPayload(body_str, collab_url)
                new_request = self.helpers.buildHttpMessage(headers, new_body)

                response = self.callbacks.makeHttpRequest(
                    message.getHttpService(), new_request
                )

                resp = response.getResponse()
                resp_info = self.helpers.analyzeResponse(resp)
                resp_body = resp[resp_info.getBodyOffset():]
                resp_str = self.helpers.bytesToString(resp_body)

                if self.is_ssrf_successful(resp_str):
                    self.updateOrAddRow([url.toString(), collab_url, "Reflected", "Triggered"])
                else:
                    self.collab_mapping[collab_url] = url.toString()
                    self.start_times[collab_url] = time.time()
                    self.updateOrAddRow([url.toString(), collab_url, "Waiting", "Waiting"])

            except Exception as e:
                print("[SSRFDetector] processRequest error:", e)

        Thread(target=run).start()

    def injectPayload(self, body, payload):
        body_str = body
        for k in ["url", "redirect", "target", "next", "returnurl", "callback"]:
            body_str = re.sub(r'(?i)(' + k + r')=([^&]+)', r'\1=' + payload, body_str)

        try:
            j = json.loads(body_str)
            for k in j:
                if k.lower() in ["url", "redirect", "target", "next", "returnurl", "callback"]:
                    j[k] = payload
            body_str = json.dumps(j)
        except:
            pass

        return self.helpers.stringToBytes(body_str)

    # ================= Collaborator 检查 =================

    def checkCollaborator(self, event=None):
        self._checkCollaborator()

    def _checkCollaborator(self):
        try:
            interactions = self.collaborator.fetchAllCollaboratorInteractions()
            for data in interactions:
                pid = data.getProperty("interaction_id").lower()
                for k in list(self.collab_mapping.keys()):
                    sub = k.replace("http://", "").split(".")[0].lower()
                    if pid == sub:
                        self.updateOrAddRow([self.collab_mapping[k], k, data.getProperty("protocol"), "Triggered"])
                        self.collab_mapping.pop(k, None)
                        self.start_times.pop(k, None)
        except Exception as e:
            print("[SSRFDetector] collaborator error:", e)

    def autoCheckCollaborator(self):
        while self.keep_checking:
            self._checkCollaborator()
            time.sleep(30)

    def updateOrAddRow(self, row):
        def ui():
            payload = row[1]
            if payload in self.row_map:
                self.table_model.data[self.row_map[payload]] = row
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
