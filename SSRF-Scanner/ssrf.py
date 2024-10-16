from burp import IBurpExtender, IMessageEditorController, ITab, IContextMenuFactory, IParameter
from java.awt import GridBagLayout, GridBagConstraints, Insets, Color, Font, Dimension, BorderLayout, FontMetrics, FlowLayout
from javax.swing import JTabbedPane, JComboBox, JTable, ListSelectionModel, JPopupMenu, JMenuItem, SwingUtilities, Box, JTextArea, JMenuItem, JFrame, JPanel, JButton, JLabel, JTextField, JSplitPane, SwingConstants, JCheckBox, JScrollPane, BorderFactory, BoxLayout
from java.util import ArrayList
from java.awt.event import ActionListener, MouseAdapter
from javax.swing.event import ListSelectionListener
from java.net import URL
from urlparse import urlparse
from javax.swing.table import AbstractTableModel

import javax.swing.JFileChooser as JFileChooser
import threading
import json
import base64
import difflib
import os
import shutil
import subprocess
import time
import sys
import urllib


class BurpExtender(IBurpExtender, IMessageEditorController, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SSRF tester")
        self.requests = []
        self.clean_directory()

        self.config = self.load_config()

        self.ui_manager = UIManager()
        
        def launch_action(
            protocol_http, protocol_https, protocol_ftp, protocol_gopher, protocol_file, protocol_dict, protocol_ldap, protocol_smb,
            domain_ip, domain_domain, domain_localhost, domain_aws, domain_fixed,
            testing_ports, top_ports, endpoint_file, domain_url_encode, domain_double_url_encode, endpoint_url_encode, endpoint_double_url_encode
        ):
            protocols = []
            ips = []
            endpoints = []
            ports = []
            url_array = []

            if protocol_http : protocols.append("http")
            if protocol_https : protocols.append("https")
            if protocol_ftp : protocols.append("ftp")
            if protocol_gopher : protocols.append("gopher")
            if protocol_file : protocols.append("file")
            if protocol_dict : protocols.append("dict")
            if protocol_ldap : protocols.append("ldap")
            if protocol_smb : protocols.append("smb")
            print(protocols)

            if domain_fixed[1]:
                ips.append(domain_fixed[0])
            else:
                if domain_ip[1]:
                    ips.extend(Utils.generate_ip_combinations(domain_ip[0]))

                if domain_localhost:
                    with open('./localhost.txt', 'r') as file:
                        for line in file:
                            ips.append(line.strip())

                if domain_domain[1]:
                    obfuscate_domains = Utils.obfuscate_domain(domain_domain[0])
                    ips.extend(obfuscate_domains)

            print(ips)

            if testing_ports[1]:
                ports = Utils.parse_ports(testing_ports[0])
                print(ports)

            elif top_ports:
                with open("./top_ports.txt", 'r') as file:
                    for line in file:
                        ports.append(line.strip())
                print(ports)

            with open(endpoint_file, 'r') as file:
                for line in file:
                    endpoints.append(line.strip())
                print(endpoints)

            for protocol in protocols:
                for ip in ips:
                    for port in ports:
                        for endpoint in endpoints:
                            if domain_url_encode:
                                ip = Utils.url_encode(ip)
                            elif domain_double_url_encode:
                                ip = Utils.double_url_encode(ip)

                            if endpoint_url_encode:
                                endpoint = Utils.url_encode(endpoint)
                            elif endpoint_double_url_encode:
                                endpoint = Utils.double_url_encode(endpoint)

                            url = protocol + "://" + ip + ":" + str(port) + "/" + endpoint
                            url_array.append(url)
            
            print(url_array)
            
            self.ui_manager.create_single_payload_frame(
                payloads=url_array,
                requests=self.requests,
                callbacks=self._callbacks,
                helpers=self._helpers,
                rate_limit=0,
                chatgpt_assist=False,
            )

        def browse_action(event, endpoint_input):
            self.ui_manager.browse_file(endpoint_input)

        self.main_tab = JPanel(BorderLayout())
        self.tabbed_pane = JTabbedPane()

        self.main_tab = JPanel(BorderLayout())
        self.tabbed_pane = JTabbedPane()

        self.ssrf_panel = JPanel()
        self.ssrf_panel.setLayout(BoxLayout(self.ssrf_panel, BoxLayout.Y_AXIS))

        self.top_panel = self.ui_manager.create_top_panel(launch_action, lambda event: browse_action(event, self.endpoint_input))
        self.ssrf_panel.add(self.top_panel)

        self.tabbed_pane.addTab("SSRF", JScrollPane(self.ssrf_panel))

        self.tabbed_pane.addTab("Test", self.create_test_subtab())

        self.main_tab.add(self.tabbed_pane, BorderLayout.CENTER)

        callbacks.customizeUiComponent(self.main_tab)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

    def create_test_subtab(self):
        test_tab_panel = JPanel(BorderLayout())
        sub_tabbed_pane = JTabbedPane()

        file_paths = {
            "Subsubtab 1 - Endpoints": "./endpoint.txt",
            "Subsubtab 2 - Top Ports": "./top_ports.txt",
            "Subsubtab 3 - Localhost": "./localhost.txt",
            "Subsubtab 4 - Cloud": "./cloud.txt"
        }
        
        for subsubtab_name, file_path in file_paths.items():
            subsubtab_panel = self.create_file_editor_panel(file_path)
            sub_tabbed_pane.addTab(subsubtab_name, subsubtab_panel)
        
        test_tab_panel.add(sub_tabbed_pane, BorderLayout.CENTER)

        return test_tab_panel

    def create_file_editor_panel(self, file_path):
        
        panel = JPanel(BorderLayout())
        
        text_area = JTextArea(20, 50)
        scroll_pane = JScrollPane(text_area)
               
        try:
            with open(file_path, 'r') as file:
                text_area.setText(file.read())
        except Exception as e:
            text_area.setText(str(e))

        save_button = JButton("Save", actionPerformed=lambda event: self.save_file_content(file_path, text_area))

        panel.add(scroll_pane, BorderLayout.CENTER)
        panel.add(save_button, BorderLayout.SOUTH)

        return panel

    def save_file_content(self,file_path, text_area):
        
        try:
            with open(file_path, 'w') as file:
                file.write(text_area.getText())
            print("Saved content to " + file_path)
        except Exception as e:
            print(str(e))

    def load_config(self):
        try:
            with open('config.json', 'r') as f:
                return json.load(f)
        except Exception as e:
            print(str(e))
            return {}

    def getTabCaption(self):
        return "SSRF"

    def getUiComponent(self):
        return self.main_tab

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Send with Params", actionPerformed=lambda event: self.add_request(invocation, "params")))
        menu_list.add(JMenuItem("Send with Headers", actionPerformed=lambda event: self.add_request(invocation, "headers")))
        menu_list.add(JMenuItem("Send with Endpoint", actionPerformed=lambda event: self.add_request(invocation, "endpoint")))
        return menu_list

    def add_request(self, invocation, mode):
        try:
            request = invocation.getSelectedMessages()[0]
            request_info = self._helpers.analyzeRequest(request)
            request_obj = Request(request, request_info, self._callbacks, self._helpers, mode)
            
            if not self.is_request_already_added(request_info):
                self.requests.append(request_obj)
                request_panel = RequestPanel(request_obj, self.ssrf_panel, self)
                self.ssrf_panel.add(request_panel)
                self.ssrf_panel.revalidate()
                self.ssrf_panel.repaint()
        except Exception as e:
            print(str(e))

    def is_request_already_added(self, new_request_info):
        new_url = new_request_info.getUrl()
        new_method = new_request_info.getMethod()
        new_params = set(param.getName() for param in new_request_info.getParameters())

        for existing_request in self.requests:
            existing_info = existing_request.request_info
            if Utils.is_same_request(existing_info, new_url, new_method, new_params):
                return True
        return False

    def clean_directory(self):
        try:
            directory = "/tmp/burp_requests"
            if os.path.exists(directory):
                shutil.rmtree(directory)
                os.makedirs(directory)
            else:
                os.makedirs(directory)
        except Exception as e:
            print("Error cleaning directory:", str(e))

    def save_request_file(self, request, param):
        try:
            request_info = self._helpers.analyzeRequest(request)
            headers = request_info.getHeaders()
            body_offset = request_info.getBodyOffset()
            body_bytes = request.getRequest()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)

            request_string = "\n".join(headers) + "\n\n" + body
            directory = "/tmp/burp_requests"
            url = request_info.getUrl()
            param_name = param.getName() if isinstance(param, IParameter) else param[0] if isinstance(param, tuple) else param
            file_path = os.path.join(directory, url.getPath().replace("/", "_") + param_name + ".txt")

            with open(file_path, 'w') as file:
                file.write(request_string)
        except Exception as e:
            print("Error saving request file:", str(e))

        return file_path
    
class TestTab(ITab):
    def __init__(self, panel):
        self.panel = panel

    def getTabCaption(self):
        return "Test"

    def getUiComponent(self):
        return self.panel


class UIManager:
    @staticmethod
    def create_top_panel(launch_action, browse_action):
        top_panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.insets = Insets(5, 5, 5, 5)  

        
        def add_horizontal_spacing(panel, x_position, y_position):
            constraints.gridx = x_position
            constraints.gridy = y_position
            panel.add(Box.createHorizontalStrut(75), constraints)  

        
        constraints.anchor = GridBagConstraints.WEST
        constraints.gridx = 0
        constraints.gridy = 0
        top_panel.add(JLabel("Protocol"), constraints)

        protocol_http_checkbox = JCheckBox("http")
        protocol_https_checkbox = JCheckBox("https")
        protocol_ftp_checkbox = JCheckBox("ftp")
        protocol_gopher_checkbox = JCheckBox("gopher")
        protocol_file_checkbox = JCheckBox("file")
        protocol_dict_checkbox = JCheckBox("dict")
        protocol_ldap_checkbox = JCheckBox("ldap")
        protocol_smb_checkbox = JCheckBox("smb")

        constraints.gridy = 1
        top_panel.add(protocol_http_checkbox, constraints)

        constraints.gridy = 2
        top_panel.add(protocol_https_checkbox, constraints)

        constraints.gridy = 3
        top_panel.add(protocol_ftp_checkbox, constraints)

        constraints.gridy = 4
        top_panel.add(protocol_gopher_checkbox, constraints)

        constraints.gridy = 5
        top_panel.add(protocol_file_checkbox, constraints)

        constraints.gridy = 6
        top_panel.add(protocol_dict_checkbox, constraints)

        constraints.gridy = 7
        top_panel.add(protocol_ldap_checkbox, constraints)

        constraints.gridy = 8
        top_panel.add(protocol_smb_checkbox, constraints)

        add_horizontal_spacing(top_panel, 1, 0)

        constraints.gridx = 2
        constraints.gridy = 0
        top_panel.add(JLabel("domain/ip"), constraints)

        domain_localhost_checkbox = JCheckBox("localhost")
        constraints.gridy = 1
        top_panel.add(domain_localhost_checkbox, constraints)

        
        domain_ip_checkbox = JCheckBox()
        domain_ip_input = JTextField("192.xx.xx.xx", 15)
        ip_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))  
        ip_panel.add(domain_ip_checkbox)
        ip_panel.add(domain_ip_input)

        constraints.gridy = 2
        top_panel.add(ip_panel, constraints)

        
        domain_domain_checkbox = JCheckBox()
        domain_domain_input = JTextField("domain.com", 15)
        domain_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        domain_panel.add(domain_domain_checkbox)
        domain_panel.add(domain_domain_input)

        constraints.gridy = 3
        top_panel.add(domain_panel, constraints)

        
        domain_aws_checkbox = JCheckBox("aws")
        constraints.gridy = 4
        top_panel.add(domain_aws_checkbox, constraints)

        
        domain_fixed_checkbox = JCheckBox()
        domain_fixed_input = JTextField("fixed", 15)
        fixed_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        fixed_panel.add(domain_fixed_checkbox)
        fixed_panel.add(domain_fixed_input)

        constraints.gridy = 5
        top_panel.add(fixed_panel, constraints)

        
        add_horizontal_spacing(top_panel, 3, 0)

        
        constraints.gridx = 4
        constraints.gridy = 0
        top_panel.add(JLabel("port"), constraints)

        ports_checkbox = JCheckBox()
        ports_input = JTextField("80, 443", 15)
        port_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        port_panel.add(ports_checkbox)
        port_panel.add(ports_input)

        constraints.gridy = 1
        top_panel.add(port_panel, constraints)

        top_ports_checkbox = JCheckBox("Top Ports")
        constraints.gridy = 2
        top_panel.add(top_ports_checkbox, constraints)

        
        add_horizontal_spacing(top_panel, 5, 0)

        
        constraints.gridx = 6
        constraints.gridy = 0
        top_panel.add(JLabel("Endpoints"), constraints)

        endpoint_file_label = JLabel("File")
        endpoint_input = JTextField("./endpoint.txt", 20)
        browse_button = JButton("Browse", actionPerformed=browse_action)

        BurpExtender.endpoint_input = endpoint_input

        constraints.gridy = 1
        constraints.gridx = 6
        top_panel.add(endpoint_file_label, constraints)
        constraints.gridx = 7
        top_panel.add(endpoint_input, constraints)
        constraints.gridx = 8
        top_panel.add(browse_button, constraints)

        domain_url_encode_checkbox = JCheckBox("Domain-Url-encode")
        constraints.gridy = 9
        constraints.gridx = 1
        top_panel.add(domain_url_encode_checkbox, constraints)

        domain_double_url_encode_checkbox = JCheckBox("Domain-Double-Url-encode")
        constraints.gridy = 9
        constraints.gridx = 2
        top_panel.add(domain_double_url_encode_checkbox, constraints)

        endpoint_url_encode_checkbox = JCheckBox("Endpoint-Url-encode")
        constraints.gridy = 9
        constraints.gridx = 3
        top_panel.add(endpoint_url_encode_checkbox, constraints)

        endpoint_double_url_encode_checkbox = JCheckBox("Endpoint-Double-Url-encode")
        constraints.gridy = 9
        constraints.gridx = 4
        top_panel.add(endpoint_double_url_encode_checkbox, constraints)

        launch_button = JButton("Launch", actionPerformed=lambda event: launch_action(
            protocol_http_checkbox.isSelected(),
            protocol_https_checkbox.isSelected(),
            protocol_ftp_checkbox.isSelected(),
            protocol_gopher_checkbox.isSelected(),
            protocol_file_checkbox.isSelected(),
            protocol_dict_checkbox.isSelected(),
            protocol_ldap_checkbox.isSelected(),
            protocol_smb_checkbox.isSelected(),
            (domain_ip_input.getText(), domain_ip_checkbox.isSelected()),
            (domain_domain_input.getText(), domain_domain_checkbox.isSelected()),
            domain_localhost_checkbox.isSelected(),
            domain_aws_checkbox.isSelected(),
            (domain_fixed_input.getText(), domain_fixed_checkbox.isSelected()),
            (ports_input.getText(), ports_checkbox.isSelected()),
            top_ports_checkbox.isSelected(),
            endpoint_input.getText(),
            domain_url_encode_checkbox.isSelected(),
            domain_double_url_encode_checkbox.isSelected(),
            endpoint_url_encode_checkbox.isSelected(),
            endpoint_double_url_encode_checkbox.isSelected(),
        ))

        
        constraints.gridy = 10
        constraints.gridx = 4
        constraints.gridwidth = 2
        top_panel.add(launch_button, constraints)

        return top_panel

    @staticmethod
    def browse_file(text_input_field):
        file_chooser = JFileChooser()
        ret = file_chooser.showOpenDialog(None)
        if ret == JFileChooser.APPROVE_OPTION:
            selected_file = file_chooser.getSelectedFile().getAbsolutePath()
            text_input_field.setText(selected_file)

    @staticmethod
    def create_find_panel(launched_request_table, table_model):
        find_panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.insets = Insets(10, 10, 10, 10)
        constraints.gridx = 0
        constraints.gridy = 0
        find_panel.add(JLabel("Pattern:", SwingConstants.RIGHT), constraints)
        find_input = JTextField(20)
        constraints.gridx = 1
        find_panel.add(find_input, constraints)
        
        
        find_button = JButton("Find", actionPerformed=lambda event: UIManager.find_function(find_input.getText(), table_model.launched_requests, table_model))
        constraints.gridx = 2
        find_panel.add(find_button, constraints)
        
        return find_panel

    @staticmethod
    def find_function(pattern, launched_requests, table_model):
        pattern_lower = pattern.lower()  
        for i, launched_request in enumerate(launched_requests):
            
            if pattern_lower in launched_request.request_body_str.lower() or pattern_lower in launched_request.body_str.lower():
                launched_request.find_result = "Found"  
            else:
                launched_request.find_result = "--"
                
            
            table_model.update_request(i, launched_request)

    @staticmethod
    def sort_launched_requests(table_model, sort_key, update_panel_callback):
        table_model.launched_requests.sort(key=lambda request: getattr(request, sort_key, ""))
        table_model.fireTableDataChanged()  
        update_panel_callback()  

    @staticmethod
    def create_sort_panel(launched_request_table, table_model, update_panel_callback):
        sort_panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.insets = Insets(10, 10, 10, 10)
        constraints.gridx = 0
        constraints.gridy = 0
        sort_panel.add(JLabel("Sort by:", SwingConstants.RIGHT), constraints)
        sort_options = ["diff", "status_code", "response_time", "unusual_headers", "unusual_content"]
        sort_combobox = JComboBox(sort_options)
        constraints.gridx = 1
        sort_panel.add(sort_combobox, constraints)
        sort_button = JButton("Sort", actionPerformed=lambda event: UIManager.sort_launched_requests(table_model, sort_combobox.getSelectedItem(), update_panel_callback))
        constraints.gridx = 2
        sort_panel.add(sort_button, constraints)
        return sort_panel

    @staticmethod
    def create_single_payload_frame(payloads, requests, callbacks, helpers, rate_limit, chatgpt_assist):
        frame = JFrame("Single Payload")
        frame.setSize(1150, 800)
        frame.setLayout(BorderLayout())
        
        launched_requests = []
        launched_request_panels = []

        table_model = LaunchedRequestTableModel(launched_requests)
        launched_request_table = JTable(table_model)
        launched_request_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

        
        launched_request_table.addMouseListener(TableMouseAdapter(launched_request_table, launched_requests))

        table_container_panel = JPanel(BorderLayout())
        table_container_panel.add(JScrollPane(launched_request_table), BorderLayout.CENTER)
        
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
        top_panel.setPreferredSize(Dimension(1000, 100))
        
        
        find_panel = UIManager.create_find_panel(launched_request_table, table_model)
        try:
            sort_panel = UIManager.create_sort_panel(launched_request_table, table_model, lambda: None)
        except Exception as e:
            print(str(e))

        request_text_area = JTextArea('Request',80,600)
        response_text_area = JTextArea('Response',80,600)
        bottom_panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(request_text_area), JScrollPane(response_text_area))
        bottom_panel.setDividerLocation(0.5)
        bottom_panel.setResizeWeight(0.5)
        
        top_panel.add(find_panel)
        top_panel.add(sort_panel)

        
        request_panels_container = JPanel()
        request_panels_container.setLayout(BoxLayout(request_panels_container, BoxLayout.Y_AXIS))
        
        
        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))
        main_panel.setPreferredSize(Dimension(1000, 450))
        main_panel.add(top_panel)
        main_panel.add(table_container_panel)
        
        frame.add(main_panel, BorderLayout.NORTH)
        frame.add(bottom_panel, BorderLayout.CENTER)
        frame.setVisible(True)

        def inject_payloads():
            for request in requests:
                for param in request.testing_params:
                    for payload in payloads:
                        try:
                            launched_request = LaunchedRequest(request, param, payload, callbacks, helpers, "params", chatgpt_assist)
                            launched_request_panel = LaunchedRequestPanel(launched_request, request_text_area, response_text_area)

                            launched_request.set_panel(launched_request_panel)

                            
                            SwingUtilities.invokeLater(lambda: launched_requests.append(launched_request))
                            SwingUtilities.invokeLater(lambda: table_model.fireTableRowsInserted(len(launched_requests) - 1, len(launched_requests) - 1))
                            SwingUtilities.invokeLater(lambda: request_panels_container.add(launched_request_panel))
                            SwingUtilities.invokeLater(lambda: request_panels_container.revalidate())
                            SwingUtilities.invokeLater(lambda: request_panels_container.repaint())

                            
                            threading.Thread(target=launched_request.modify_and_send_request).start()
                            

                            if rate_limit > 0:
                                time.sleep(rate_limit / 1000.0)
                        except Exception as e:
                            print(str(e))

                
                for header in request.testing_headers:
                    for payload in payloads:
                        try:
                            launched_request = LaunchedRequest(request, header, payload, callbacks, helpers, "headers", chatgpt_assist)
                            launched_request_panel = LaunchedRequestPanel(launched_request, request_text_area, response_text_area)

                            launched_request.set_panel(launched_request_panel)

                            
                            SwingUtilities.invokeLater(lambda: launched_requests.append(launched_request))
                            SwingUtilities.invokeLater(lambda: table_model.fireTableRowsInserted(len(launched_requests) - 1, len(launched_requests) - 1))
                            SwingUtilities.invokeLater(lambda: request_panels_container.add(launched_request_panel))
                            SwingUtilities.invokeLater(lambda: request_panels_container.revalidate())
                            SwingUtilities.invokeLater(lambda: request_panels_container.repaint())

                            
                            threading.Thread(target=launched_request.modify_and_send_request).start()
                            

                            if rate_limit > 0:
                                time.sleep(rate_limit / 1000.0)
                        except Exception as e:
                            print(str(e))

        
        try:
            threading.Thread(target=inject_payloads).start()
        except Exception as e:
            print(str(e))

        def on_row_selected(event):
            if not event.getValueIsAdjusting():  
                selected_row = launched_request_table.getSelectedRow()
                if selected_row != -1:
                    model_row = launched_request_table.convertRowIndexToModel(selected_row)
                    launched_request = launched_requests[model_row]  

                    temp_panel = LaunchedRequestPanel(launched_request, request_text_area, response_text_area)

                    formatted_request = temp_panel.format_http_request(launched_request.request_info, launched_request.request_body_str)
                    formatted_response = temp_panel.format_http_response(launched_request.response_info, launched_request.body_str)

                    request_text_area.setText(formatted_request)
                    response_text_area.setText(formatted_response)

        
        launched_request_table.getSelectionModel().addListSelectionListener(lambda event: on_row_selected(event))



class Request:
    def __init__(self, request, request_info, callbacks, helpers, mode):
        self.request = request
        self.request_info = request_info
        self.testing_params = []
        self.testing_headers = []
        self.testing_endpoints = []
        self.headers = []
        self.endpoints = []
        self._callbacks = callbacks
        self._helpers = helpers  
        self.response = None
        self.response_info = None
        self.status_code, self.body_str = "000", "<></>"
        self.mode = mode
        self.extract_testing_parts()
        threading.Thread(target=self.make_request).start()

    def extract_testing_parts(self):
        try:
            if self.mode == "params":
                self.params = self.request_info.getParameters()
            elif self.mode == "headers":
                headers = self.request_info.getHeaders()
                for header in headers[1:]:
                    if not header.lower().startswith("cookie"):
                        if ": " in header:
                            name, value = header.split(": ", 1)
                        else:
                            name, value = header, ""
                        self.headers.append((name, value))
            elif self.mode == "endpoint":
                path_segments = self.request_info.getUrl().getPath().split('/')
                self.endpoints = [segment for segment in path_segments if segment]
        except Exception as e:
            print("Error extracting testing parts:", str(e))

    def make_request(self):
        try:
            httpService = self.request.getHttpService()
            self.response = self._callbacks.makeHttpRequest(httpService, self.request.getRequest())
            if self.response:
                response_bytes = self.response.getResponse()
                if response_bytes:
                    self.status_code, self.body_str = self.analyze_response(response_bytes)
        except Exception as e:
            print("Error making request:", str(e))

    def analyze_response(self, response_bytes):
        try:
            self.response_info = self._helpers.analyzeResponse(response_bytes)
            headers = self.response_info.getHeaders()
            body_offset = self.response_info.getBodyOffset()
            body_bytes = response_bytes[body_offset:]
            status_line = headers[0]
            status_code = status_line.split()[1]
            body_str = self._helpers.bytesToString(body_bytes)
            return status_code, body_str
        except Exception as e:
            print("Error analyzing response:", str(e))
            return "000", "<></>"

class LaunchedRequest:
    def __init__(self, request, param, payload, callbacks, helpers, mode, chatGPT):
        self.original_request = request
        self.request_bytes = self.original_request.request.getRequest()[:]
        self.param = param
        self.payload = payload
        self._callbacks = callbacks
        self._helpers = helpers
        self.mode = mode
        self.chatGPT = chatGPT
        self.panel = None
        self.response = None
        self.response_info = None
        self.diff = '--'
        self.find_result = ""
        self.status_code, self.body_str, self.response_time = "--", "<></>", "--"
        self.unusual_headers, self.unusual_content, self.find_result = "--", "--", "--"
        self.modified_request_bytes = None 
        threading.Thread(target=self.modify_and_send_request).start()

    def set_panel(self, panel):
        self.panel = panel

    def modify_and_send_request(self):
        try:
            new_request_bytes = self.modify_request()
            self.modified_request_bytes = new_request_bytes  
            httpService = self.original_request.request.getHttpService()
            start_time = time.time()
            self.response = self._callbacks.makeHttpRequest(httpService, new_request_bytes)
            end_time = time.time()
            self.response_time = end_time - start_time
            response_bytes = self.response.getResponse()
            self.status_code, self.body_str = self.analyze_response(response_bytes)
        except Exception as e:
            print("Error modifying and sending request:", str(e))
        
        try:
            self.response_info = self._helpers.analyzeResponse(response_bytes)
        except Exception as e:
            print("Error analyzing response info:", str(e))
            self.response_info = None

        if self.panel:
            try:
                self.diff = Utils.compare_response_bodies(self.body_str, self.original_request.body_str)
                self.unusual_headers = Utils.check_unsual_header(self.original_request.response_info.getHeaders(), self.response_info.getHeaders())
            except Exception as e:
                print(str(e))    
            if self.chatGPT:
                self.unusual_content = Utils.check_unusual_content(self.body_str)
            self.panel.update_panel(self.status_code, self.diff, self.response_time, self.unusual_headers, self.unusual_content)

    def modify_request(self):
        try:
            new_request_bytes = self.request_bytes[:]
            self.request_info = self._helpers.analyzeRequest(self.original_request.request)
            body_offset = self.request_info.getBodyOffset()
            request_body_bytes = new_request_bytes[body_offset:]
            self.request_body_str = self._helpers.bytesToString(request_body_bytes)
        except Exception as e:
            print("Error modifying request:", str(e))

        try:
            request_body_json = json.loads(self.request_body_str)
            is_json = True
        except Exception:
            is_json = False

        if is_json:
            new_request_bytes = self.modify_json_request(new_request_bytes, request_body_json, body_offset)
        else:
            new_request_bytes = self.modify_non_json_request(new_request_bytes)

        return self.update_content_length(new_request_bytes)

    def modify_json_request(self, new_request_bytes, request_body_json, body_offset):
        try:
            if self.param.getName() in request_body_json:
                original_value = request_body_json[self.param.getName()]
                try:
                    if isinstance(original_value, int):
                        self.payload = int(self.payload)
                    elif isinstance(original_value, float):
                        self.payload = float(self.payload)
                    elif isinstance(original_value, bool):
                        self.payload = self.payload.lower() in ['true', '1', 'yes']
                except ValueError:
                    pass
                
                request_body_json[self.param.getName()] = self.payload
                new_request_body_str = json.dumps(request_body_json)
                new_request_bytes = new_request_bytes[:body_offset] + self._helpers.stringToBytes(new_request_body_str)
                self.request_info = self._helpers.analyzeRequest(new_request_bytes)
                body_offset = self.request_info.getBodyOffset()
                new_request_body_bytes = new_request_bytes[body_offset:]
                self.request_body_str = self._helpers.bytesToString(new_request_body_bytes)
            else:
                new_request_bytes = self.modify_parameters(new_request_bytes)
        except Exception as e:
            print("Error modifying JSON request:", str(e))
        return new_request_bytes

    def modify_non_json_request(self, new_request_bytes):
        try:
            if self.mode == "headers":
                new_request_bytes = self.modify_headers(new_request_bytes)
            elif self.mode == "endpoint":
                new_request_bytes = self.modify_endpoints(new_request_bytes)
            else:  
                new_request_bytes = self.modify_parameters(new_request_bytes)

            self.request_info = self._helpers.analyzeRequest(new_request_bytes)
            body_offset = self.request_info.getBodyOffset()
            new_request_body_bytes = new_request_bytes[body_offset:]
            self.request_body_str = self._helpers.bytesToString(new_request_body_bytes)
        except Exception as e:
            print("Error modifying non-JSON request:", str(e))
        return new_request_bytes

    def modify_parameters(self, new_request_bytes):
        try:
            if self.param is None:
                print("Warning: Parameter is None, skipping parameter modification.")
                return new_request_bytes

            for parameter in self.request_info.getParameters():
                if parameter.getName() == self.param.getName() and parameter.getType() == self.param.getType():
                    new_request_bytes = self._helpers.removeParameter(new_request_bytes, parameter)
                    new_param = self._helpers.buildParameter(self.param.getName(), self.payload, parameter.getType())
                    new_request_bytes = self._helpers.addParameter(new_request_bytes, new_param)
                    self.request_info = self._helpers.analyzeRequest(new_request_bytes)
                    body_offset = self.request_info.getBodyOffset()
                    new_request_body_bytes = new_request_bytes[body_offset:]
                    self.request_body_str = self._helpers.bytesToString(new_request_body_bytes)
        except Exception as e:
            print("Error modifying parameters:", str(e))
        return new_request_bytes

    def modify_headers(self, new_request_bytes):
        try:
            headers = self.request_info.getHeaders()
            new_headers = []
            for header in headers:
                if header.lower().startswith(self.param[0].lower() + ":"):
                    new_headers.append(self.param[0] + ": " + self.payload)
                else:
                    new_headers.append(header)
            return self._helpers.buildHttpMessage(new_headers, new_request_bytes[self.request_info.getBodyOffset():])
        except Exception as e:
            print("Error modifying headers:", str(e))
            return new_request_bytes

    def modify_endpoints(self, new_request_bytes):
        try:
            url = urlparse(self.request_info.getUrl().toString())
            path_segments = url.path.split('/')
            new_path = "/".join([self.payload if segment == self.param else segment for segment in path_segments])
            new_url = url.scheme + "://" + url.netloc + new_path

            initial_request_bytes = self._helpers.buildHttpRequest(URL(new_url))
            initial_request_str = self._helpers.bytesToString(initial_request_bytes)
            initial_request_headers = initial_request_str.split("\r\n\r\n", 1)[0]
            initial_new_request_info = self._helpers.analyzeRequest(self._helpers.stringToBytes(initial_request_headers))
            new_headers = initial_new_request_info.getHeaders()

            for i in range(len(new_headers)):
                if new_headers[i].lower().startswith("host:"):
                    new_headers[i] = "Host: " + url.netloc

            new_request_bytes = self._helpers.buildHttpMessage(new_headers, new_request_bytes[self.request_info.getBodyOffset():])
            self.request_info = self._helpers.analyzeRequest(new_request_bytes)
        except Exception as e:
            print("Error modifying endpoints:", str(e))
        return new_request_bytes

    def update_content_length(self, new_request_bytes):
        try:
            self.request_info = self._helpers.analyzeRequest(new_request_bytes)
            body_offset = self.request_info.getBodyOffset()
            new_request_body_bytes = new_request_bytes[body_offset:]
            content_length = len(new_request_body_bytes)

            headers = self.request_info.getHeaders()
            new_headers = [header for header in headers if not header.lower().startswith("content-length:")]
            new_headers.append("Content-Length: " + str(content_length))

            return self._helpers.buildHttpMessage(new_headers, new_request_body_bytes)
        except Exception as e:
            print("Error updating content length:", str(e))
            return new_request_bytes

    def analyze_response(self, response_bytes):
        try:
            response_info = self._helpers.analyzeResponse(response_bytes)
            headers = response_info.getHeaders()
            body_offset = response_info.getBodyOffset()
            body_bytes = response_bytes[body_offset:]
            status_line = headers[0]
            status_code = status_line.split()[1]
            body_str = self._helpers.bytesToString(body_bytes)
            return status_code, body_str
        except Exception as e:
            print("Error analyzing response:", str(e))
            return "000", "<></>"

class RequestPanel(JPanel):
    def __init__(self, request, parent_panel, burp_extender):
        super(RequestPanel, self).__init__(GridBagLayout())
        self.request = request
        self.parent_panel = parent_panel
        self.burp_extender = burp_extender
        self.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0, 0.1), 2))
        self.add_request_components(request)

    def add_request_components(self, request):
        constraints = GridBagConstraints()
        constraints.insets = Insets(10, 10, 10, 10)
        constraints.anchor = GridBagConstraints.WEST
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.weightx = 1

        constraints.gridx = 0
        constraints.gridy = 0
        constraints.gridwidth = 4
        request_label = JLabel(str(request.request.getUrl()))
        request_label.setFont(Font("Dialog", Font.BOLD, 19))
        self.add(request_label, constraints)
        constraints.gridx = 5
        constraints.gridy = 0
        constraints.gridwidth = 1
        constraints.weightx = 0
        constraints.anchor = GridBagConstraints.EAST
        delete_button = JButton("X", actionPerformed=self.delete_request)
        self.add(delete_button, constraints)

        constraints.gridwidth = 1
        constraints.weightx = 0
        constraints.anchor = GridBagConstraints.WEST
        constraints.gridx = 0
        constraints.gridy = 1

        param_type_map = {0: "Get", 1: "Body", 2: "Cookie", 3: "XML", 4: "JSON", 5: "AMF", 6: "Multipart Attribute", 7: "WebSocket"}
        for index, param in enumerate(request.params if request.mode == "params" else
                                      request.headers if request.mode == "headers" else
                                      request.endpoints):
            constraints.gridy = index + 2
            if request.mode == "params":
                param_type = param_type_map.get(param.getType(), "Unknown")
                checkbox_label = param.getName() + " (" + param_type + ")"
            elif request.mode == "headers":
                checkbox_label = param[0] + " (Header)"
            else:
                checkbox_label = param + " (Endpoint)"
            checkbox = JCheckBox(checkbox_label)
            checkbox.setOpaque(False)
            checkbox.addActionListener(CheckboxActionListener(request, param))
            self.add(checkbox, constraints)

    def delete_request(self, event):
        self.parent_panel.remove(self)
        self.parent_panel.revalidate()
        self.parent_panel.repaint()
        self.burp_extender.requests.remove(self.request)

class LaunchedRequestPanel(JPanel):
    def __init__(self, launched_request, request_text_area, response_text_area):
        self.launchedRequest = launched_request
        self.request_text_area = request_text_area
        self.response_text_area = response_text_area
        self.setupUI()
        self.addMouseListener(PanelMouseListener(self))
        self.init_context_menu()

    def setupUI(self):
        self.setLayout(BoxLayout(self, BoxLayout.X_AXIS))
        self.setPreferredSize(Dimension(1100, 30))
        self.setMaximumSize(Dimension(sys.maxint, 30))
        self.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0, 0.1), 2))

        url = urlparse(self.launchedRequest.original_request.request_info.getUrl().toString())
        endpoint = url.path
        method = self.launchedRequest.original_request.request_info.getMethod()
        title = method + " - " + endpoint
        
        self.request_label = JLabel(title)
        self.request_label.setFont(Font("Dialog", Font.BOLD, 18))
        
        param = (self.launchedRequest.param.getName() 
                 if isinstance(self.launchedRequest.param, IParameter) 
                 else self.launchedRequest.param[0] 
                 if isinstance(self.launchedRequest.param, tuple) 
                 else self.launchedRequest.param)
        self.param_label = JLabel(param)
        
        status = str(self.launchedRequest.status_code)
        self.status_label = JLabel(status)
        
        diff = str(self.launchedRequest.diff)+"%"
        self.diff_label = JLabel(diff)
        
        
        try:
            response_time = str(int((self.launchedRequest.response_time * 1000)))+" ms"
        except (TypeError, ValueError):
            response_time = "-- ms"
        self.time_label = JLabel(response_time)
        
        unusual_content = str(self.launchedRequest.unusual_content)
        self.content_label = JLabel(unusual_content)
        
        unusual_headers = str(self.launchedRequest.unusual_headers)
        self.headers_label = JLabel(unusual_headers)
        
        find_result = str(self.launchedRequest.find_result)
        self.find_label = JLabel(find_result)
        
        self.set_label_sizes()
        self.add(self.request_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.param_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.status_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.diff_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.time_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.content_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.headers_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.find_label)

    def set_label_sizes(self):
        size = Dimension(175, 30)
        for label in [self.request_label, self.param_label, self.status_label, self.diff_label, self.time_label, self.content_label, self.headers_label, self.find_label]:
            label.setPreferredSize(size)
        self.request_label.setPreferredSize(Dimension(500, 30))

    def update_panel(self, status_code, diff, response_time, unusual_headers, unusual_content):
        def update_components():
            self.status_label.setText(status_code)
            self.diff_label.setText(str(diff)+"%") 
            response_time_ms = str(int(response_time * 1000)) + " ms"
            self.time_label.setText(response_time_ms)
            self.content_label.setText(unusual_content)
            self.headers_label.setText(unusual_headers)
            self.revalidate()
            self.repaint()
        SwingUtilities.invokeLater(update_components)

    def update_find(self, result):
        def update_find_panel():
            self.find_label.setText(result)
            self.revalidate()
            self.repaint()
        SwingUtilities.invokeLater(update_find_panel)

    def on_panel_clicked(self):
        formatted_request = self.format_http_request(self.launchedRequest.request_info, self.launchedRequest.request_body_str)
        formatted_response = self.format_http_response(self.launchedRequest.response_info, self.launchedRequest.body_str)
        SwingUtilities.invokeLater(lambda: self.request_text_area.setText(formatted_request))
        SwingUtilities.invokeLater(lambda: self.response_text_area.setText(formatted_response))

    @staticmethod
    def format_http_request(request_info, body):
        headers = "\n".join(request_info.getHeaders())
        return headers + "\n\n" + body

    @staticmethod
    def format_http_response(response_info, body):
        headers = "\n".join(response_info.getHeaders())
        return headers + "\n\n" + body

    def get_sort_value(self, sort_key):
        return getattr(self.launchedRequest, sort_key, "")

    def init_context_menu(self):
        self.context_menu = JPopupMenu()
        send_to_repeater_item = JMenuItem("Send to Repeater", actionPerformed=self.send_to_repeater)
        self.context_menu.add(send_to_repeater_item)
        self.addMouseListener(MouseAdapterContextMenu(self))

    def send_to_repeater(self, event):
        request_info = self.launchedRequest.original_request.request_info
        http_service = self.launchedRequest.original_request.request.getHttpService()
        modified_request_bytes = self.launchedRequest.modified_request_bytes
        self.launchedRequest._callbacks.sendToRepeater(http_service.getHost(), http_service.getPort(), http_service.getProtocol == 'https', modified_request_bytes, None)

class MouseAdapterContextMenu(MouseAdapter):
    def __init__(self, panel):
        self.panel = panel

    def mousePressed(self, event):
        self.checkForTriggerEvent(event)

    def mouseReleased(self, event):
        self.checkForTriggerEvent(event)

    def checkForTriggerEvent(self, event):
        if event.isPopupTrigger():
            self.panel.context_menu.show(event.getComponent(), event.getX(), event.getY())

class CheckboxActionListener(ActionListener):
    def __init__(self, request, param):
        self.request = request
        self.param = param

    def actionPerformed(self, event):
        checkbox = event.getSource()
        try:
            if checkbox.isSelected():
                if self.param not in (self.request.testing_params if self.request.mode == "params" else
                                      self.request.testing_headers if self.request.mode == "headers" else
                                      self.request.testing_endpoints):
                    (self.request.testing_params if self.request.mode == "params" else
                     self.request.testing_headers if self.request.mode == "headers" else
                     self.request.testing_endpoints).append(self.param)
            else:
                if self.param in (self.request.testing_params if self.request.mode == "params" else
                                  self.request.testing_headers if self.request.mode == "headers" else
                                  self.request.testing_endpoints):
                    (self.request.testing_params if self.request.mode == "params" else
                     self.request.testing_headers if self.request.mode == "headers" else
                     self.request.testing_endpoints).remove(self.param)
        except Exception as e:
            print("Error handling checkbox action:", str(e))

class PanelMouseListener(MouseAdapter):
    def __init__(self, panel):
        self.panel = panel

    def mouseClicked(self, event):
        self.panel.on_panel_clicked()

class LaunchedRequestTableModel(AbstractTableModel):
    column_names = ["Request", "Parameter", "Status Code", "Difference", "Response Time", "AI Analysis", "Headers Changes", "Find Result"]

    def __init__(self, launched_requests):
        self.launched_requests = launched_requests

    def getColumnCount(self):
        return len(self.column_names)

    def getRowCount(self):
        return len(self.launched_requests)

    def getColumnName(self, col):
        return self.column_names[col]

    def getValueAt(self, row, col):
        request = self.launched_requests[row]
        if isinstance(request, LaunchedRequest):
            if col == 0:
                return str(request.original_request.request_info.getUrl().getPath())
            elif col == 1:
                return str(request.param.getName() if isinstance(request.param, IParameter) else request.param)
            elif col == 2:
                return str(request.status_code)
            elif col == 3:
                return str(request.diff) + "%"
            elif col == 4:
                try:
                    response_time_ms = int(request.response_time * 1000)
                    return str(response_time_ms) + " ms"
                except (TypeError, ValueError):
                    return "-- ms"
            elif col == 5:
                return str(request.unusual_content)
            elif col == 6:
                return str(request.unusual_headers)
            elif col == 7:
                return str(request.find_result)  
        return ""

    def isCellEditable(self, row, col):
        return False

    def update_request(self, row, request):
        self.launched_requests[row] = request
        self.fireTableRowsUpdated(row, row)

class TableMouseAdapter(MouseAdapter):
    def __init__(self, table, launched_requests):
        self.table = table
        self.launched_requests = launched_requests

    def mousePressed(self, event):
        self.handle_event(event)

    def mouseReleased(self, event):
        self.handle_event(event)

    def handle_event(self, event):
        if event.isPopupTrigger():  
            row = self.table.rowAtPoint(event.getPoint())
            if row != -1:
                self.table.setRowSelectionInterval(row, row)
                launched_request = self.launched_requests[row]
                self.show_context_menu(event, launched_request)

    def show_context_menu(self, event, launched_request):
        context_menu = JPopupMenu()
        send_to_repeater_item = JMenuItem("Send to Repeater", actionPerformed=lambda e: self.send_to_repeater(launched_request))
        context_menu.add(send_to_repeater_item)
        context_menu.show(event.getComponent(), event.getX(), event.getY())

    def send_to_repeater(self, launched_request):
        request_info = launched_request.original_request.request_info
        http_service = launched_request.original_request.request.getHttpService()
        modified_request_bytes = launched_request.modified_request_bytes
        launched_request._callbacks.sendToRepeater(http_service.getHost(), http_service.getPort(),
                                                   http_service.getProtocol() == 'https', modified_request_bytes, None)

class Utils:
    @staticmethod
    def is_base64_encoded(data):
        try:
            return base64.b64encode(base64.b64decode(data)) == data
        except Exception:
            return False

    @staticmethod
    def compare_response_bodies(body1, body2):
        semilarity = difflib.SequenceMatcher(None, body1, body2)
        difference = 100 - int(semilarity.ratio() * 100)
        return difference

    @staticmethod
    def check_unsual_header(headers_list, new_headers_list):
        try:
            headers = Utils.parse_headers(headers_list)
            new_headers = Utils.parse_headers(new_headers_list)
            ignore_headers = ["Date", "Server", "Content-Length", "Expires", "Cache-Control", "ETag", "Last-Modified", "Vary", "Connection", "Transfer-Encoding"]
            header_weights = {"Set-Cookie": 10, "Content-Type": 8, "X-Frame-Options": 5, "X-XSS-Protection": 5, "X-Content-Type-Options": 5, "Strict-Transport-Security": 7, "Referrer-Policy": 6}
            default_weight = 1
            filtered_headers1 = {k: v for k, v in headers.items() if k not in ignore_headers}
            filtered_headers2 = {k: v for k, v in new_headers.items() if k not in ignore_headers}
            total_weight = 0
            total_difference = 0
            all_headers = set(filtered_headers1.keys()).union(set(filtered_headers2.keys()))

            for header in all_headers:
                weight = header_weights.get(header, default_weight)
                value1 = filtered_headers1.get(header, "")
                value2 = filtered_headers2.get(header, "")
                similarity = difflib.SequenceMatcher(None, value1, value2)
                if similarity.ratio() < 0.100:
                    total_difference += weight
                total_weight += weight

            if total_weight == 0:
                return "0"

            return str(total_difference)
        except Exception as e:
            print(str(e))
            return "error"

    @staticmethod
    def check_unusual_content(body):
        prompt = "Im gonna give you a http response, your job is to give me the problility of it being vulnerable and to what exactly. so your response would be something \
            like '70% sql injection' or '90% file inclusion'. and if it doesnt have any indication of vulnerability say only 'Nothing'. if its less than 40% , say nothing. the response is to a request injected with some malicious payload. So if the response doesnt clearly show a vulnerable response, say 'nothing'. dont hallucinate, be precise and dont give long answers :"
        prompt += "\n Response: \n\n"
        prompt += body
        print(prompt)
        try:
            command = ['python', 'ai.py', prompt]
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                return stderr
            
            return stdout
        
        except Exception as e:
            return str(e)

    @staticmethod
    def parse_headers(header_list):
        headers_dict = {}
        for header in header_list:
            if ":" in header:
                key, value = header.split(":", 1)
                headers_dict[key.strip()] = value.strip()
        return headers_dict

    @staticmethod
    def is_same_request(existing_info, new_url, new_method, new_params):
        existing_url = existing_info.getUrl()
        existing_method = existing_info.getMethod()
        existing_params = set(param.getName() for param in existing_info.getParameters())
        
        return (new_url.getPath() == existing_url.getPath() and
                new_method == existing_method and
                new_params == existing_params)
    
    @staticmethod
    def generate_ip_combinations(ip_pattern):
        parts = ip_pattern.split(".")
        
        result = [""]

        for part in parts:
            new_result = []
            if part == "xx":
                new_result = [existing_ip + str(i) + "." for existing_ip in result for i in range(1, 256)]
            elif "-" in part:
                start, end = map(int, part.split("-"))
                new_result = [existing_ip + str(i) + "." for existing_ip in result for i in range(start, end + 1)]
            elif "," in part:
                options = part.split(",")
                new_result = [existing_ip + opt + "." for existing_ip in result for opt in options]
            else:
                new_result = [existing_ip + part + "." for existing_ip in result]
            
            result = new_result

        result = [ip.rstrip(".") for ip in result]
        
        return result

    @staticmethod
    def obfuscate_domain(domain):
        obfuscated_domains = set()

        
        obfuscated_domains.add(urllib.quote(domain))
        obfuscated_domains.add(domain.replace('.', '%2E'))

        
        mixed_encoded = domain.replace('e', '%65').replace('o', '%6F')
        obfuscated_domains.add(mixed_encoded)
        mixed_encoded = domain.replace('.', '%2E')
        obfuscated_domains.add(mixed_encoded)

        
        obfuscated_domains.add(domain.upper())
        obfuscated_domains.add(domain.lower())
        obfuscated_domains.add(domain.capitalize())
        obfuscated_domains.add(''.join([char.upper() if i % 2 == 0 else char.lower() for i, char in enumerate(domain)]))

        
        obfuscated_domains.add(domain + '.')
        
        
        fully_encoded = ''.join('%' + format(ord(c), '02X') for c in domain)
        obfuscated_domains.add(fully_encoded)

        
        obfuscated_domains.add(domain + '%00')
        obfuscated_domains.add(domain + '%00.example.com')

        
        try:
            obfuscated_domains.add(domain.encode('idna').decode('ascii'))
        except Exception:
            pass

        
        obfuscated_domains.add(domain[::-1])

        
        obfuscated_domains.add('www.' + domain)
        obfuscated_domains.add('sub.' + domain)
        obfuscated_domains.add(domain + '.fake.com')

        
        if '.' in domain:
            dotless = domain.split('.')[0]
            obfuscated_domains.add(dotless)


        
        combo1 = urllib.quote(domain) + '.'
        combo2 = ''.join('%' + format(ord(c), '02X') for c in domain[::-1]) + '%00'
        obfuscated_domains.add(combo1)
        obfuscated_domains.add(combo2)

        return list(obfuscated_domains)
    
    @staticmethod
    def parse_ports(port_string):
        ports = set() 

        port_parts = port_string.split(',')

        for part in port_parts:
            part = part.strip()
            if '-' in part:  
                try:
                    start, end = map(int, part.split('-'))
                    ports.update(range(start, end + 1))
                except ValueError:
                    raise ValueError("Invalid range: "+part)
            else:  
                try:
                    ports.add(int(part))
                except ValueError:
                    raise ValueError("Invalid port: "+ part)

        return sorted(ports)

    @staticmethod
    def url_encode(input_string):
        return ''.join('%{:02X}'.format(ord(c)) for c in input_string)

    @staticmethod
    def double_url_encode(input_string):
        de = Utils.url_encode(input_string)
        return Utils.url_encode(de)