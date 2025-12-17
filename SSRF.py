# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IParameter
from javax.swing import JPanel, JButton, JLabel, JScrollPane, JTable, BoxLayout, JMenuItem, JPopupMenu
from javax.swing.table import AbstractTableModel
from java.util import ArrayList
from java.awt import Dimension
from threading import Thread
from javax.swing import SwingUtilities
from java.awt.event import MouseAdapter
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

        self.collab_mapping = {}  # payload -> url mapping
        self.start_times = {}     # payload -> send timestamp

        self.table_data = []
        self.row_map = {}  # payload -> row index for quick update

        self.initUI()
        callbacks.addSuiteTab(self)

        self.keep_checking = True
        t = Thread(target=self.autoCheckCollaborator)
        t.setDaemon(True)
        t.start()

    def initUI(self):
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))

        self.label = JLabel("SSRF Detection Results:")
        self.panel.add(self.label)

        self.table_model = SimpleTableModel(self.table_data,
                                            ["Request URL", "Collaborator Payload", "Interaction Type", "Status"])
        self.table = JTable(self.table_model)
        self.table.setPreferredScrollableViewportSize(Dimension(700, 300))
        scroll = JScrollPane(self.table)
        self.panel.add(scroll)

        self.refreshButton = JButton("Check Collaborator", actionPerformed=self.checkCollaborator)
        self.panel.add(self.refreshButton)

        self.clearButton = JButton("Clear Records", actionPerformed=lambda e: self.clearRecords())
        self.panel.add(self.clearButton)

        # 右键菜单
        self.popup = JPopupMenu()
        clearMenuItem = JMenuItem("Clear Records", actionPerformed=lambda e: self.clearRecords())
        self.popup.add(clearMenuItem)

        # 绑定自定义鼠标监听器，处理右键菜单弹出
        self.table.addMouseListener(TableMouseListener(self.popup))

    def clearRecords(self):
        def clear():
            self.table_model.data = []
            self.row_map = {}
            self.collab_mapping = {}
            self.start_times = {}
            self.table_model.fireTableDataChanged()
        SwingUtilities.invokeLater(clear)

    def getTabCaption(self):
        return "SSRF Detector"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        menu_list = ArrayList()
        if messages:
            menu_item = JMenuItem("Send to SSRF Detector", actionPerformed=lambda e: self.processRequest(messages[0]))
            menu_list.add(menu_item)
        return menu_list

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # 必须实现IHttpListener接口，暂时不做处理
        pass

    import re

    def is_ssrf_successful(self, response_text):
        match = re.search(r"<body>\s*([a-zA-Z0-9]{20,40})\s*</body>", response_text)
        if match:
            print("[SSRFDetector] Reflected SSRF match body content:", match.group(1))
            return True
        return False

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
                params = analyzed.getParameters()
                for p in params:
                    if p.getType() == IParameter.PARAM_URL and p.getName().lower() in param_names:
                        new_param = self.helpers.buildParameter(p.getName(), collab_url, p.getType())
                        new_request = self.helpers.updateParameter(new_request, new_param)

                # 处理POST body参数
                analyzed_new = self.helpers.analyzeRequest(new_request)
                body = new_request[analyzed_new.getBodyOffset():]
                body_str = self.helpers.bytesToString(body)
                headers = analyzed_new.getHeaders()

                content_type = ""
                for h in headers:
                    if h.lower().startswith("content-type:"):
                        content_type = h.lower()
                        break

                # 替换body中指定参数
                new_body = self.injectPayload(body_str, content_type, collab_url)
                new_request = self.helpers.buildHttpMessage(headers, new_body)

                # 发请求并拿响应
                response = self.callbacks.makeHttpRequest(message.getHttpService(), new_request)
                resp_bytes = response.getResponse()
                resp_analyzed = self.helpers.analyzeResponse(resp_bytes)
                resp_body = resp_bytes[resp_analyzed.getBodyOffset():]
                resp_str = self.helpers.bytesToString(resp_body)

                # 判断回显型SSRF
                if self.is_ssrf_successful(resp_str):
                    self.updateOrAddRow([url.toString(), collab_url, "Reflected SSRF", "Payload found in response"])
                    self.collab_mapping.pop(collab_url, None)
                    self.start_times.pop(collab_url, None)
                else:
                    self.collab_mapping[collab_url] = url.toString()
                    self.start_times[collab_url] = time.time()
                    self.updateOrAddRow([url.toString(), collab_url, "Waiting for callback", "Waiting"])

            except Exception as e:
                print("Error in processRequest:", e)

        Thread(target=run).start()

    def injectPayload(self, body, content_type, payload):
        try:
            param_names = ["url", "redirect", "target", "next", "returnurl", "callback"]
            body_str = self.helpers.bytesToString(body)

            for param in param_names:
                pattern = re.compile(r'(?i)(' + param + r')=([^&\s]+)')
                body_str = pattern.sub(r'\1=' + payload, body_str)

            try:
                json_body = json.loads(body_str)
                changed = False
                for k in json_body:
                    if k.lower() in param_names:
                        json_body[k] = payload
                        changed = True
                if changed:
                    body_str = json.dumps(json_body)
            except:
                pass

            return self.helpers.stringToBytes(body_str)
        except Exception as e:
            print("Error in injectPayload:", e)
            return body

    def checkCollaborator(self, event=None):
        self._checkCollaborator()

    def _checkCollaborator(self):
        try:
            interaction_details_list = self.collaborator.fetchAllCollaboratorInteractions()
            print("[SSRFDetector] Fetched %d collaborator interactions" % len(interaction_details_list))
            print("[SSRFDetector] Current tracked payloads: %s" % list(self.collab_mapping.keys()))

            for data in interaction_details_list:
                payload = data.getProperty("interaction_id")
                protocol = data.getProperty("protocol")
                full_url = data.getProperty("client")

                print("[SSRFDetector] Interaction found: id=%s, protocol=%s, client=%s" % (payload, protocol, full_url))

                payload_lower = payload.lower()
                to_remove = None

                for tracked_payload in list(self.collab_mapping.keys()):
                    tracked_subdomain = tracked_payload.replace("http://", "").split(".")[0].lower()
                    if payload_lower == tracked_subdomain:
                        print("[SSRFDetector] Matched interaction for payload: %s" % tracked_payload)
                        self.updateOrAddRow([self.collab_mapping[tracked_payload], tracked_payload, protocol, "Triggered"])
                        to_remove = tracked_payload
                        break

                if to_remove:
                    self.collab_mapping.pop(to_remove, None)
                    self.start_times.pop(to_remove, None)

        except Exception as e:
            print("[SSRFDetector] Error in _checkCollaborator:", e)

    def autoCheckCollaborator(self):
        while self.keep_checking:
            self._checkCollaborator()
            now = time.time()
            to_update = []
            for k, t in list(self.start_times.items()):
                if now - t > 180:
                    to_update.append(k)

            for k in to_update:
                self.updateOrAddRow([self.collab_mapping.get(k, "(unknown)"), k, "None", "No SSRF (3min timeout)"])
                # 保留等待记录，如果想删除取消注释下面两行：
                # self.collab_mapping.pop(k, None)
                # self.start_times.pop(k, None)

            time.sleep(30)

    def updateOrAddRow(self, row):
        def update():
            payload = row[1]
            if payload in self.row_map:
                idx = self.row_map[payload]
                self.table_model.data[idx] = row
                self.table_model.fireTableRowsUpdated(idx, idx)
            else:
                self.table_model.data.append(row)
                self.row_map[payload] = len(self.table_model.data) - 1
                self.table_model.fireTableRowsInserted(len(self.table_model.data) - 1, len(self.table_model.data) - 1)
        SwingUtilities.invokeLater(update)


class SimpleTableModel(AbstractTableModel):
    def __init__(self, data, columns):
        self.data = data
        self.columns = columns

    def getRowCount(self):
        return len(self.data)

    def getColumnCount(self):
        return len(self.columns)

    def getValueAt(self, row, col):
        return self.data[row][col]

    def getColumnName(self, col):
        return self.columns[col]

    def fireTableRowsUpdated(self, firstRow, lastRow):
        self.fireTableDataChanged()

    def fireTableRowsInserted(self, firstRow, lastRow):
        self.fireTableDataChanged()

    def addRow(self, row):
        self.data.append(row)
        self.fireTableDataChanged()
