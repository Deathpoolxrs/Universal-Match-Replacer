from burp import IBurpExtender
from burp import ISessionHandlingAction
from burp import ITab
from javax import swing
from java import awt
from types import *
import re
from java.awt import Color

class BurpExtender(IBurpExtender, ITab, ISessionHandlingAction):
    matchreplacestart = False
    
    def registerExtenderCallbacks(self, callback_2):
        # set our extension name
        callback_2.setExtensionName("Universal Match Replacer")
        self._helpers = callback_2.getHelpers()
        self._callbackRef = callback_2
        callback_2.registerSessionHandlingAction(self)

        # Tab Match replace
        self._jPanelMatchreplace = swing.JPanel()
        self._jPanelMatchreplace.setLayout(awt.GridBagLayout())
        self._jPanelMatchreplaceConstraints = awt.GridBagConstraints()

        # UI Match Replace
        # label
        self._jLabelMPInfo = swing.JLabel("Universal Match Replacer")
        self._jLabelMPInfo.setForeground(Color.RED)
        self._jPanelMatchreplaceConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelMatchreplaceConstraints.gridx = 0
        self._jPanelMatchreplaceConstraints.gridy = 0
        self._jPanelMatchreplaceConstraints.gridwidth = 2
        self._jPanelMatchreplace.add(self._jLabelMPInfo, self._jPanelMatchreplaceConstraints)

        # Lists to hold dynamically created fields
        self.regex_text_fields = []
        self.replacement_text_fields = []

        # Function to add new regex and replacement text fields
        def addRegexField():
            index = len(self.regex_text_fields) + 1
            regex_text_field = swing.JTextField("Enter Regex {}".format(index), 12)
            self._jPanelMatchreplaceConstraints.fill = awt.GridBagConstraints.HORIZONTAL
            self._jPanelMatchreplaceConstraints.gridx = 0
            self._jPanelMatchreplaceConstraints.gridy = index + 1 # Adjust the grid position as needed
            self._jPanelMatchreplace.add(regex_text_field, self._jPanelMatchreplaceConstraints)
            self.regex_text_fields.append(regex_text_field)

            replacement_text_field = swing.JTextField("Enter Text to Replace {}".format(index), 18)
            self._jPanelMatchreplaceConstraints.fill = awt.GridBagConstraints.HORIZONTAL
            self._jPanelMatchreplaceConstraints.gridx = 1  # Adjust the column for replacement text field
            self._jPanelMatchreplaceConstraints.gridy = index + 1  # Same row as regex text field
            self._jPanelMatchreplace.add(replacement_text_field, self._jPanelMatchreplaceConstraints)
            self.replacement_text_fields.append(replacement_text_field)

            # Refresh the UI
            self._jPanelMatchreplace.revalidate()
            self._jPanelMatchreplace.repaint()

        # Button to add more regex and replacement text fields
        self._jAddRegexFieldButton = swing.JButton("Add Regex Field", actionPerformed=lambda e: addRegexField())
        self._jPanelMatchreplaceConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelMatchreplaceConstraints.gridx = 0
        self._jPanelMatchreplaceConstraints.gridy = 1  # Initial position, adjust as needed
        self._jPanelMatchreplaceConstraints.gridwidth = 1
        self._jPanelMatchreplace.add(self._jAddRegexFieldButton, self._jPanelMatchreplaceConstraints)

        # Button to submit
        self._jSetregex = swing.JButton("Submit", actionPerformed=self.startmatchreplace)
        self._jPanelMatchreplaceConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelMatchreplaceConstraints.gridx = 1  # Initial column, adjust as needed
        self._jPanelMatchreplaceConstraints.gridy = 1  # Initial position, adjust as needed
        self._jPanelMatchreplace.add(self._jSetregex, self._jPanelMatchreplaceConstraints)

        # Button to clear
        self._jtextclear = swing.JButton("Clean", actionPerformed=self.mrclear)
        self._jPanelMatchreplaceConstraints.fill = awt.GridBagConstraints.HORIZONTAL
        self._jPanelMatchreplaceConstraints.gridx = 2  # Initial column, adjust as needed
        self._jPanelMatchreplaceConstraints.gridy = 1  # Initial position, adjust as needed
        self._jPanelMatchreplace.add(self._jtextclear, self._jPanelMatchreplaceConstraints)

        # Create Match Replace Panel
        self._jConfigTab = swing.JTabbedPane()
        self._jConfigTab.addTab("Match Replace", self._jPanelMatchreplace)
        callback_2.customizeUiComponent(self._jConfigTab)
        callback_2.addSuiteTab(self)

    # Implement ISessionHandlingAction
    def getActionName(self):
        return "Universal Match Replacer"

    # Implement ITab
    def getTabCaption(self):
        return 'Universal Match Replacer'

    def getUiComponent(self):
        return self._jConfigTab

    # Function to find header and body of request
    def getRequestHeadersAndBody(self, content):
        request = content.getRequest()
        request_data = self._helpers.analyzeRequest(request)
        headers = list(request_data.getHeaders() or '')
        body = request[request_data.getBodyOffset():].tostring()
        return headers, body

    # Function to find response headers
    def getResponseHeadersAndBody(self, content):
        request = content.getResponse()
        request_data = self._helpers.analyzeResponse(request)
        headers = list(request_data.getHeaders() or '')
        body = request[request_data.getBodyOffset():].tostring()
        return headers, body

    def startmatchreplace(self, e):
        self.matchreplacestart = True
        self.mr_regexes = [field.getText() for field in self.regex_text_fields]
        self.mr_texts = [field.getText() for field in self.replacement_text_fields]
        self._jSetregex.setEnabled(False)

    def mrclear(self, e):
        for field in self.regex_text_fields:
            self._jPanelMatchreplace.remove(field)
        for field in self.replacement_text_fields:
            self._jPanelMatchreplace.remove(field)

        self.mr_regexes = []
        self.mr_texts = []
        self.matchreplacestart = False
        self._jSetregex.setEnabled(True)
        self.regex_text_fields = []
        self.replacement_text_fields = []

    # This function is used to process HTTP messages
    def performAction(self, currentRequest, macroItems):
        if self.matchreplacestart:
            headers = self._helpers.analyzeRequest(currentRequest).getHeaders()
            request_body = currentRequest.getRequest()[self._helpers.analyzeRequest(currentRequest).getBodyOffset():].tostring()
            
            for regex, text in zip(self.mr_regexes, self.mr_texts):
                # Process headers
                for i, header in enumerate(headers):
                    headers[i] = re.sub(regex, text, header)

                # Process body
                request_body = re.sub(regex, text, request_body)

            new_request = self._helpers.buildHttpMessage(headers, request_body)
            currentRequest.setRequest(new_request)
