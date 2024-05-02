import difflib
from burp import IBurpExtender, IMessageEditorController, ITab, IContextMenuFactory
from java.awt import GridBagLayout, GridBagConstraints, Insets, Color, Font, Dimension, BorderLayout
from javax.swing import SwingUtilities, Box, JTextArea, JMenuItem, JFrame, JPanel, JButton, JLabel, JTextField, JSplitPane, SwingConstants, JCheckBox, JScrollPane, BorderFactory, BoxLayout
from java.util import ArrayList
from java.awt.event import ActionListener, MouseAdapter
from java.net import URL
from urlparse import urlparse
import threading

def compare_response_bodies(body1, body2):
    seq = difflib.SequenceMatcher(None, body1, body2)
    similarity = seq.ratio() * 100 
    return str(similarity)

class Request:
    def __init__(self, request, request_info, callbacks, helpers):
        self.request = request
        self.request_info = request_info
        self.testing_params = []
        self._callbacks = callbacks
        self._helpers = helpers  # Store the helpers object
        self.normal_response = None
        self.status_code, self.body_str = "000","<></>"

        # Start a thread to handle the HTTP request
        threading.Thread(target=self.make_request).start()

    def make_request(self):
        httpService = self.request.getHttpService()
        self.normal_response = self._callbacks.makeHttpRequest(httpService, self.request.getRequest())
        if self.normal_response:
            response_bytes = self.normal_response.getResponse()
            if response_bytes:
                self.status_code, self.body_str = self.analyzeResponse(response_bytes)
            else:
                print("Response bytes are None")
        else:
            print("Response object is None")

    def analyzeResponse(self, response_bytes):
        response_info = self._helpers.analyzeResponse(response_bytes)

        # Get headers and body from the response info
        headers = response_info.getHeaders()
        body_offset = response_info.getBodyOffset()
        body_bytes = response_bytes[body_offset:]  # Extract the body part of the response

        # Extract status code from the first header (status line)
        status_line = headers[0]  # HTTP/1.1 200 OK
        status_code = status_line.split()[1]  # Split the status line and get the code

        # Convert body bytes to a string (assuming UTF-8 encoding)
        body_str = self._helpers.bytesToString(body_bytes)

        return status_code, body_str


class LaunchedRequest:
    def __init__(self, request, param, payload, callbacks, helpers):
        self.request = request
        self.param = param
        self.payload = payload
        self._callbacks = callbacks
        self._helpers = helpers
        self.panel = None
        self.response = None
        self.diff = '--'
        self.status_code, self.body_str = "--","<></>"

        # Start a thread to handle the HTTP request and response analysis
        threading.Thread(target=self.modify_and_send_request).start()

    def set_panel(self, panel):
        self.panel = panel

    def modify_and_send_request(self):
        new_request_bytes = self.request.request.getRequest()
        httpService = self.request.request.getHttpService()
        for parameter in self.request.request_info.getParameters():
            if parameter.getName() == self.param:
                new_request_bytes = self._helpers.removeParameter(new_request_bytes, parameter)
                new_param = self._helpers.buildParameter(self.param, self.payload, parameter.getType())
                new_request_bytes = self._helpers.addParameter(new_request_bytes, new_param)

        self.request_info = self._helpers.analyzeResponse(new_request_bytes)
        body_offset = self.request_info.getBodyOffset()
        request_body_bytes = new_request_bytes[body_offset:]
        self.request_body_str = self._helpers.bytesToString(request_body_bytes)            

        self.response = self._callbacks.makeHttpRequest(httpService, new_request_bytes)
        response_bytes = self.response.getResponse()
        self.status_code, self.body_str = self.analyzeResponse(response_bytes)
        self.response_info = self._helpers.analyzeResponse(response_bytes)
        self.diff = compare_response_bodies(self.body_str, self.request.body_str)
        self.panel.update_panel(self.status_code, self.diff)
        print('updated normalement')

    def analyzeResponse(self, response_bytes):
        response_info = self._helpers.analyzeResponse(response_bytes)

        # Get headers and body from the response info
        headers = response_info.getHeaders()
        body_offset = response_info.getBodyOffset()
        body_bytes = response_bytes[body_offset:]  # Extract the body part of the response

        # Extract status code from the first header (status line)
        status_line = headers[0]  # HTTP/1.1 200 OK
        status_code = status_line.split()[1]  # Split the status line and get the code

        body_str = self._helpers.bytesToString(body_bytes)

        return status_code, body_str
        

class CheckboxActionListener(ActionListener):
    def __init__(self, request, param):
        self.request = request
        self.param = param

    def actionPerformed(self, event):
        checkbox = event.getSource()
        if checkbox.isSelected():
            if self.param not in self.request.testing_params:
                self.request.testing_params.append(self.param)
        else:
            if self.param in self.request.testing_params:
                self.request.testing_params.remove(self.param)

class PanelMouseListener(MouseAdapter):
    def __init__(self, panel):
        self.panel = panel

    def mouseClicked(self, event):
        self.panel.onPanelClicked()

class RequestPanel(JPanel):
    def __init__(self, request):
        super(RequestPanel, self).__init__(GridBagLayout())
        self.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0, 0.1), 2))
        self.add_request_component(request)

    def add_request_component(self, request):
        constraints = GridBagConstraints()
        constraints.insets = Insets(10, 10, 10, 10)
        constraints.anchor = GridBagConstraints.WEST
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.weightx = 1
        constraints.gridx = 0
        constraints.gridy = 0
        constraints.gridwidth = GridBagConstraints.REMAINDER
        request_label = JLabel(str(request.request.getUrl()))
        request_label.setFont(Font("Dialog", Font.BOLD, 25))
        self.add(request_label, constraints)
        constraints.gridwidth = 1

        for index, param in enumerate(request.request_info.getParameters()):
            constraints.gridy = index + 1
            checkbox = JCheckBox(param.getName())
            checkbox.setOpaque(False)
            checkbox.addActionListener(CheckboxActionListener(request,param.getName()))
            self.add(checkbox, constraints)

class LaunchedRequestPanel(JPanel):
    def __init__(self, launchedRequest, request_text_area, response_text_area):
        self.launchedRequest = launchedRequest
        self.setupUI()
        self.addMouseListener(PanelMouseListener(self))
        self.response_text_area = response_text_area
        self.request_text_area = request_text_area
        
    def setupUI(self):
        self.setLayout(BoxLayout(self, BoxLayout.X_AXIS))
        self.setPreferredSize(Dimension(800, 30))
        self.setMaximumSize(Dimension(sys.maxint, 30))
        self.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0, 0.1), 2))

        # Endpoint Extracting
        url = urlparse(self.launchedRequest.request.request_info.getUrl().toString())
        endpoint = url.path

        # Create labels for each piece of data
        self.request_label = JLabel(endpoint)
        self.request_label.setFont(Font("Dialog", Font.BOLD, 20))
        self.param_label = JLabel(self.launchedRequest.param)
        self.status_label = JLabel(self.launchedRequest.status_code)
        self.diff_label = JLabel(self.launchedRequest.diff)

        # Optionally set the preferred size for each label to control the layout
        self.request_label.setPreferredSize(Dimension(175, 30))
        self.param_label.setPreferredSize(Dimension(175, 30))
        self.status_label.setPreferredSize(Dimension(175, 30))
        self.diff_label.setPreferredSize(Dimension(175, 30))

        # Add the labels to the panel with spacing
        self.add(self.request_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))  # Spacing between components
        self.add(self.param_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))  # Spacing between components
        self.add(self.status_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))  # Spacing between components
        self.add(self.diff_label)
    
    def update_panel(self, status_code, diff):
        # Update multiple components safely on the EDT
        def update_components():
            self.status_label.setText(status_code)
            self.diff_label.setText(diff)
            self.revalidate()
            self.repaint()

        SwingUtilities.invokeLater(update_components)

    def onPanelClicked(self):
        print("clicked")
        formatted_request = self.format_http_request(self.launchedRequest.request, self.launchedRequest.request_body_str)
        formatted_response = self.format_http_response(self.launchedRequest.response_info, self.launchedRequest.body_str)
        
        SwingUtilities.invokeLater(lambda: self.request_text_area.setText(formatted_request))
        SwingUtilities.invokeLater(lambda: self.response_text_area.setText(formatted_response))

    
    def format_http_request(self, request, body):
        request_info = request.request_info
        headers = ""
        for header in request_info.getHeaders():
            headers += header+ "\n"
        return headers + "\n" + body
    
    def format_http_response(self, response_info, body):
        headers = ""
        for header in response_info.getHeaders():
            headers += header + "\n"
        return headers + "\n" + body


class UIManager:
    @staticmethod
    def create_top_panel(launch_action):
        top_panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.insets = Insets(10, 10, 10, 10)
        constraints.gridx = 0
        constraints.gridy = 0
        top_panel.add(JLabel("Payload:", SwingConstants.RIGHT), constraints)
        payload_input = JTextField(20)
        constraints.gridx = 1
        top_panel.add(payload_input, constraints)
        launch_button = JButton("Launch", actionPerformed=lambda event: launch_action(payload_input.getText()))
        constraints.gridx = 2
        top_panel.add(launch_button, constraints)
        return top_panel, payload_input

    @staticmethod
    def launch_frame(payload, requests, callbacks, helpers):
        frame = JFrame("Intruder-like Frame")
        frame.setSize(1000, 650)
        frame.setLayout(BorderLayout())
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

        request_text_area = JTextArea('Request', 10, 400)
        response_text_area = JTextArea('Response', 10, 400)
        bottom_panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(request_text_area), JScrollPane(response_text_area))
        bottom_panel.setDividerLocation(0.5)
        bottom_panel.setResizeWeight(0.5)

        for request in requests:
            for param in request.testing_params:
                launchedRequest = LaunchedRequest(request, param, payload, callbacks, helpers)
                request_panel = LaunchedRequestPanel(launchedRequest, request_text_area, response_text_area)
                launchedRequest.set_panel(request_panel)
                top_panel.add(request_panel)

        scrollable_top_panel = JScrollPane(top_panel)
        scrollable_top_panel.setPreferredSize(Dimension(1000, 300))

        frame.add(scrollable_top_panel, BorderLayout.NORTH)
        frame.add(bottom_panel, BorderLayout.CENTER)
        
        frame.setVisible(True)

class BurpExtender(IBurpExtender, IMessageEditorController, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Payload Extension")

        self.requests = []

        self.ui_manager = UIManager()
        self.top_panel, self.payload_input = UIManager.create_top_panel(lambda payload: UIManager.launch_frame(payload, self.requests, self._callbacks, self._helpers))

        self.main_panel = JPanel()
        self.main_panel.setLayout(BoxLayout(self.main_panel, BoxLayout.Y_AXIS))
        self.main_panel.add(self.top_panel)

        self.scroll_panel = JScrollPane(self.main_panel)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Right UI"

    def getUiComponent(self):
        return self.scroll_panel

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Send to Right UI", actionPerformed=lambda event: self.add_request(invocation)))
        return menu_list

    def add_request(self, invocation):
        request = invocation.getSelectedMessages()[0]
        request_info = self._helpers.analyzeRequest(request)
        url = request_info.getUrl()
        request_obj = Request(request, request_info, self._callbacks, self._helpers)
        self.requests.append(request_obj)
        request_component = RequestPanel(request_obj)
        self.main_panel.add(request_component)
        self.main_panel.revalidate()

BurpExtender()
