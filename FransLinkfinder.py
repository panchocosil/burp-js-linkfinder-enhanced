# -*- coding: utf-8 -*-
#
#  BurpJSLinkFinder Enhanced - Link & Sensitive Data Finder
#  Enhanced version with sensitive data detection capabilities
#
#  Original work by Frans Hendrik Botes (2019)
#  This repository contains a modified/enhanced version and is not the original release
#
#  Original Credit: https://github.com/GerbenJavado/LinkFinder for the idea and regex
#
from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, List
from java.util.regex import Matcher, Pattern
import binascii
import base64
import re
from javax import swing
from java.awt import Font, Color
from threading import Thread
from array import array
from java.awt import EventQueue
from java.lang import Runnable
from thread import start_new_thread
from javax.swing import JFileChooser

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

# Needed params

JSExclusionList = ['jquery', 'google-analytics','gpt.js']

# MIME types that indicate JavaScript (Burp/Content-Type can vary)
# e.g. script, application/javascript, application/x-javascript (DependencyHandler.axd, etc.)
JS_MIME_SUBSTRINGS = ('script', 'javascript', 'x-javascript', 'x-js')

# Enable/disable sensitive data detection
ENABLE_SENSITIVE_DATA_DETECTION = True

LOAD_MESSAGE = "Burp JS LinkFinder loaded."
VERSION_NOTICE = "Modified/enhanced version based on original work by Frans Hendrik Botes (2019)"
MAX_LOG_CHARS = 200000
MAX_ISSUE_ENDPOINTS = 10

def escape_html(text):
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))

class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpJSLinkFinder + Sensitive Data")

        callbacks.issueAlert("BurpJSLinkFinder + Sensitive Data Scanner enabled")

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerScannerCheck(self)
        self.initUI()
        self.callbacks.addSuiteTab(self)
        
        print (LOAD_MESSAGE)
        print (VERSION_NOTICE)
        self.outputTxtArea.setText(LOAD_MESSAGE + "\n" + VERSION_NOTICE + "\n")

    def initUI(self):
        self.tab = swing.JPanel()

        # UI for Output
        self.outputLabel = swing.JLabel("LinkFinder Log:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.outputLabel.setForeground(Color(255,102,52))
        self.logPane = swing.JScrollPane()
        self.outputTxtArea = swing.JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)
        self.clearBtn = swing.JButton("Clear Log", actionPerformed=self.clearLog)
        self.exportBtn = swing.JButton("Export Log", actionPerformed=self.exportLog)
        self.parentFrm = swing.JFileChooser()



        # Layout
        layout = swing.GroupLayout(self.tab)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        self.tab.setLayout(layout)
      
        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )
        
        layout.setVerticalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )

    def getTabCaption(self):
        return "BurpJSLinkFinder"

    def getUiComponent(self):
        return self.tab

    def clearLog(self, event):
          self.outputTxtArea.setText(LOAD_MESSAGE + "\n" + VERSION_NOTICE + "\n" )

    def appendLog(self, message):
        self.outputTxtArea.append(message)
        log_text = self.outputTxtArea.getText()
        if len(log_text) <= MAX_LOG_CHARS:
            return
        overflow = len(log_text) - MAX_LOG_CHARS
        trim_at = log_text.find("\n", overflow)
        if trim_at == -1:
            trimmed_text = log_text[-MAX_LOG_CHARS:]
        else:
            trimmed_text = log_text[trim_at + 1:]
        self.outputTxtArea.setText(trimmed_text)

    def exportLog(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.logPane, "Choose file")
        filename = chooseFile.getSelectedFile().getCanonicalPath()
        print("\n" + "Export to : " + filename)
        open(filename, 'w', 0).write(self.outputTxtArea.text)

    
    def doPassiveScan(self, ihrr):
        
        try:
            urlReq = ihrr.getUrl()
            testString = str(urlReq)
            # Consider as JS: URL contains ".js" OR path ends with /js OR response MIME is JavaScript
            mime_type = self.helpers.analyzeResponse(ihrr.getResponse()).getStatedMimeType()
            is_js_url = ".js" in testString or testString.rstrip("/").endswith("/js")
            is_js_response = mime_type and any(s in mime_type.lower() for s in JS_MIME_SUBSTRINGS)
            if not (is_js_url or is_js_response):
                return None
            linkA = linkAnalyse(ihrr, self.helpers)
            # Exclude casual JS files by URL
            if any(x in testString for x in JSExclusionList):
                print("\n" + "[-] URL excluded " + str(urlReq))
            else:
                self.appendLog("\n" + "[+] Valid URL found: " + str(urlReq))
                issues = ArrayList()
                
                # Analizar enlaces
                endpoints = linkA.analyseURL()
                for counter, endpoint in enumerate(endpoints):
                    self.appendLog("\n" + "\t[LINK] " + str(counter) + ' - ' + endpoint['link'])
                
                # Analizar información sensible (si está habilitado)
                if ENABLE_SENSITIVE_DATA_DETECTION:
                    try:
                        encoded_resp = binascii.b2a_base64(ihrr.getResponse())
                        decoded_resp = base64.b64decode(encoded_resp)
                        sensitive_analyzer = SensitiveDataAnalyzer(ihrr, self.helpers)
                        sensitive_findings = sensitive_analyzer.analyze(decoded_resp)
                        
                        if sensitive_findings:
                            self.appendLog("\n" + "\t[!] Informacion sensible detectada:")
                            for finding in sensitive_findings:
                                severity_marker = "[HIGH]" if finding['severity'] == 'High' else "[MEDIUM]" if finding['severity'] == 'Medium' else "[LOW]"
                                self.appendLog("\n" + "\t  " + severity_marker + " " + finding['type'] + ": " + finding['value'][:100])
                            # Crear issue separado para información sensible
                            issues.add(SensitiveDataIssue(ihrr, self.helpers, sensitive_findings))
                    except Exception as e:
                        print("Error analizando información sensible: " + str(e))
                
                # Issue para enlaces (siempre)
                issues.add(SRI(ihrr, self.helpers, endpoints))
                return issues
        except UnicodeEncodeError:
            print ("Error in URL decode.")
        return None


    def consolidateDuplicateIssues(self, isb, isa):
        return -1

    def extensionUnloaded(self):
        print("Burp JS LinkFinder unloaded")
        return

class linkAnalyse():
    
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres
        

    # Delimiters: " ' ` (template literals)
    # Extensions: + svc, asmx, do, cgi, pl, cfm, config; paths with 1-6 char extensions
    regex_str = """
    
      (?:"|'|`)                             # Start delimiter: quote or backtick
    
      (
        ((?:[a-zA-Z]{1,10}://|//)           # Scheme: http(s), ws(s), //, etc.
        [^"'`/]{1,}\.                       # Domain (must contain a dot)
        [a-zA-Z]{2,}[^"'`]{0,})            # TLD and path
    
        |
    
        ((?:/|\.\./|\./)                    # Paths: /, ../, ./
        [^"'`><,;| *()(%%$^/\\\[\]]         # First char restrictions
        [^"'`><,;|()]{1,})                  # Rest of path
    
        |
    
        ([a-zA-Z0-9_\-/]{1,}/               # Relative: segment/
        [a-zA-Z0-9_.\-/]{1,}                # resource name (allow dotted filenames)
        \.(?:[a-zA-Z]{1,6}|action)          # .ext (1-6 chars) or .action
        (?:[\?|/][^"'`|]{0,}|))            # Optional ? or / and params
    
        |
    
        ([a-zA-Z0-9_.\-]{1,}                # Filename.extension (allow dotted filenames)
        \.(?:php|asp|aspx|ashx|asmx|svc|jsp|json|do|cgi|pl|cfm|
             action|html|htm|js|mjs|cjs|jsx|ts|tsx|vue|txt|xml|yaml|yml|config|map) # Common backend/API extensions
        (?:\?[^"'`|]{0,}|))                # Optional query
    
        |
    
        ([a-zA-Z0-9_\-]{1,}                 # Handler without extension
        \?[^"'`|]{0,})                      # ?query
    
      )
    
      (?:"|'|`)                             # End delimiter
    
    """     

    def	parser_file(self, content, regex_str, mode=1, more_regex=None, no_dup=1):
        #print ("TEST parselfile #2")
        regex = re.compile(regex_str, re.VERBOSE)
        items = []
        for m in re.finditer(regex, content):
            link = next((g for g in m.groups() if g is not None), None)
            if link:
                items.append({"link": link})
        if no_dup:
            # Remove duplication
            all_links = set()
            no_dup_items = []
            for item in items:
                if item["link"] not in all_links:
                    all_links.add(item["link"])
                    no_dup_items.append(item)
            items = no_dup_items
    
        # Match Regex
        filtered_items = []
        for item in items:
            # Remove other capture groups from regex results
            if more_regex:
                if re.search(more_regex, item["link"]):
                    #print ("TEST parselfile #3")
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
        return filtered_items

    # Potential for use in the future...
    def threadAnalysis(self):
        thread = Thread(target=self.analyseURL(), args=(session,))
        thread.daemon = True
        thread.start()

    def analyseURL(self):
        endpoints = []
        mime_type = self.helpers.analyzeResponse(self.reqres.getResponse()).getStatedMimeType()
        if not mime_type or not any(s in mime_type.lower() for s in JS_MIME_SUBSTRINGS):
            return endpoints
        try:
            encoded_resp = binascii.b2a_base64(self.reqres.getResponse())
            decoded_resp = base64.b64decode(encoded_resp)
            endpoints = self.parser_file(decoded_resp, self.regex_str)
        except Exception:
            pass
        return endpoints


class SensitiveDataAnalyzer():
    """Detecta información sensible: credenciales, tokens, API keys, etc."""
    
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres
        
    # Patrones para detectar información sensible
    SENSITIVE_PATTERNS = [
        # API Keys comunes - solo cuando el nombre de variable es explícitamente api_key/apikey/apiKey
        {
            'name': 'API Key',
            'pattern': r'(?:api[_-]?key|apikey|apiKey|API_KEY|APIKEY)[\'"\s:=]+["\']?([A-Za-z0-9_\-/+=]{20,})["\']?(?=[,;\s\)\]}])',
            'severity': 'High',
            'flags': re.IGNORECASE
        },
        # JWT Tokens (formato: eyJ...)
        {
            'name': 'JWT Token',
            'pattern': r'(?:eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})',
            'severity': 'High'
        },
        # OAuth/Bearer Tokens
        {
            'name': 'Bearer Token',
            'pattern': r'(?:Authorization|authorization|bearer|access[_-]?token|id[_-]?token|refresh[_-]?token|token)["\s:=]+(?:Bearer\s+)?["\']?([A-Za-z0-9\-._~+/=]{12,400})',
            'severity': 'High',
            'flags': re.IGNORECASE
        },
        # AWS Access Keys (AKIA...)
        {
            'name': 'AWS Access Key',
            'pattern': r'(?:(?:AKIA|ASIA)[0-9A-Z]{16})',
            'severity': 'High'
        },
        # AWS Secret Keys
        {
            'name': 'AWS Secret Key',
            'pattern': r'(?:aws[_-]?secret(?:[_-]?access)?[_-]?key|AWS_SECRET_ACCESS_KEY|secretAccessKey)["\s:=]+["\']?([A-Za-z0-9/+=]{40})',
            'severity': 'High',
            'flags': re.IGNORECASE
        },
        # Passwords hardcodeados
        {
            'name': 'Hardcoded Password',
            'pattern': r'(?:password|passwd|pwd)["\s:=]+["\']([^"\']{8,})["\']',
            'severity': 'High',
            'flags': re.IGNORECASE
        },
        # Database connection strings
        {
            'name': 'Database Connection String',
            'pattern': r'(?:mysql|postgresql|mongodb(?:\+srv)?|mssql|oracle|redis)://[^\s"\'\`]+',
            'severity': 'High',
            'flags': re.IGNORECASE
        },
        # Private Keys (RSA, SSH)
        {
            'name': 'Private Key',
            'pattern': r'(?:-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{64,}?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----)',
            'severity': 'High'
        },
        # Email addresses (pueden ser sensibles)
        {
            'name': 'Email Address',
            'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'severity': 'Low'
        },
        # URLs con credenciales (user:pass@host)
        {
            'name': 'URL with Credentials',
            'pattern': r'(?:https?|ftp)://[^\s"\'\`:@]+:[^\s"\'\`:@]+@[^\s"\'\`]+',
            'severity': 'High'
        },
        # GitHub tokens
        {
            'name': 'GitHub Token',
            'pattern': r'(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9_]{20,255}|ghr_[A-Za-z0-9_]{40,255}|github_pat_[A-Za-z0-9_]{40,255})',
            'severity': 'High'
        },
        # GitLab tokens
        {
            'name': 'GitLab Token',
            'pattern': r'(?:(?:glpat|gloas|gldt|glrt(?:r)?|glcbt|glptt|glft|glimt|glagent|glwt|glsoat)-[A-Za-z0-9\-_]{20,255})',
            'severity': 'High'
        },
        # Google credentials
        {
            'name': 'Google Credential',
            'pattern': r'(?:AIza[0-9A-Za-z\-_]{35}|GOCSPX-[0-9A-Za-z\-_]{20,}|ya29\.[0-9A-Za-z\-_]+)',
            'severity': 'High'
        },
        # Slack tokens and webhooks
        {
            'name': 'Slack Secret',
            'pattern': r'(?:xox(?:a|b|p|r|s|e|o)(?:-[0-9A-Za-z]{1,}){2,}|https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+)',
            'severity': 'High'
        },
        # Stripe keys
        {
            'name': 'Stripe Key',
            'pattern': r'(?:(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,})',
            'severity': 'High'
        },
        # OpenAI API keys
        {
            'name': 'OpenAI API Key',
            'pattern': r'(?:sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,})',
            'severity': 'High'
        },
        # Anthropic API keys
        {
            'name': 'Anthropic API Key',
            'pattern': r'(?:sk-ant-(?:api\d{2}-)?[A-Za-z0-9_\-]{20,})',
            'severity': 'High'
        },
        # Generic secret/credential patterns
        {
            'name': 'Secret/Credential',
            'pattern': r'(?:secret|credential|auth[_-]?token|api[_-]?secret)["\s:=]+["\']([a-zA-Z0-9_\-/+=]{16,})["\']',
            'severity': 'Medium',
            'flags': re.IGNORECASE
        },
        # Hashes sueltos (standalone) - MD5 32 hex, SHA1 40 hex, SHA256 64 hex
        # Word boundary para no matchear dentro de cadenas mas largas
        {
            'name': 'MD5 Hash (standalone)',
            'pattern': r'\b([a-fA-F0-9]{32})\b',
            'severity': 'Low'
        },
        {
            'name': 'SHA1 Hash (standalone)',
            'pattern': r'\b([a-fA-F0-9]{40})\b',
            'severity': 'Low'
        },
        {
            'name': 'SHA256 Hash (standalone)',
            'pattern': r'\b([a-fA-F0-9]{64})\b',
            'severity': 'Low'
        }
    ]
    
    def analyze(self, content):
        """Analiza el contenido y retorna lista de información sensible encontrada."""
        findings = []
        seen = set()  # Para evitar duplicados
        
        for pattern_def in self.SENSITIVE_PATTERNS:
            try:
                flags = pattern_def.get('flags', 0)
                regex = re.compile(pattern_def['pattern'], flags)
                for match in regex.finditer(content):
                    # Extraer el valor capturado o el match completo
                    if match.groups():
                        value = match.group(1) if match.lastindex else match.group(0)
                    else:
                        value = match.group(0)
                    
                    # Evitar falsos positivos comunes
                    if self._is_false_positive(value):
                        continue
                    
                    # Evitar duplicados: para hashes (valor corto y solo hex) usar valor completo
                    if len(value) <= 64 and re.match(r'^[a-fA-F0-9]+$', value):
                        key = (pattern_def['name'], value)
                    else:
                        key = (pattern_def['name'], value[:50])
                    if key in seen:
                        continue
                    seen.add(key)
                    
                    findings.append({
                        'type': pattern_def['name'],
                        'value': value[:200],  # Limitar longitud para UI
                        'severity': pattern_def['severity'],
                        'position': match.start()
                    })
            except Exception as e:
                # Si un patrón falla, continuar con los demás
                print("Error en patrón %s: %s" % (pattern_def['name'], str(e)))
                continue
        
        return findings
    
    def _is_false_positive(self, value):
        """Filtra falsos positivos comunes."""
        # Valores comunes que no son credenciales reales
        false_positives = [
            'example.com', 'localhost', '127.0.0.1',
            'your-api-key', 'your-secret', 'placeholder',
            'test', 'demo', 'sample', 'dummy'
        ]
        value_lower = value.lower()
        if any(fp in value_lower for fp in false_positives):
            return True
        
        # Excluir hashes triviales (todo ceros o mismo caracter repetido)
        if re.match(r'^[a-fA-F0-9]+$', value) and len(value) in (32, 40, 64):
            if len(set(value.lower())) <= 1:
                return True
        
        # Excluir nombres de funciones/métodos comunes de JavaScript (camelCase o con mayúsculas)
        # Si el valor parece un nombre de función (empieza con minúscula, tiene camelCase), probablemente es falso positivo
        if len(value) > 15 and value[0].islower() and any(c.isupper() for c in value[1:]):
            # Verificar si parece un nombre de función común
            js_function_patterns = [
                'handler', 'callback', 'function', 'method', 'component',
                'ref', 'mount', 'unmount', 'will', 'did', 'setstate',
                'getelement', 'addevent', 'removeevent', 'preventdefault',
                'inner', 'outer', 'slider', 'toggle', 'enable', 'disable'
            ]
            value_lower_words = value_lower.replace('_', ' ').replace('-', ' ')
            if any(pattern in value_lower_words for pattern in js_function_patterns):
                return True
        
        return False


class SensitiveDataIssue(IScanIssue):
    """Issue para información sensible encontrada en JS."""
    
    def __init__(self, reqres, helpers, findings):
        self.helpers = helpers
        self.reqres = reqres
        self.findings = findings
        
    def getHost(self):
        return self.reqres.getHost()
    
    def getPort(self):
        return self.reqres.getPort()
    
    def getProtocol(self):
        return self.reqres.getProtocol()
    
    def getUrl(self):
        return self.reqres.getUrl()
    
    def getIssueName(self):
        return "Sensitive Data Found in JavaScript"
    
    def getIssueType(self):
        return 0x08000000
    
    def getSeverity(self):
        # Usar la severidad más alta encontrada
        severities = [f['severity'] for f in self.findings]
        if 'High' in severities:
            return "High"
        elif 'Medium' in severities:
            return "Medium"
        return "Low"
    
    def getConfidence(self):
        return "Certain"
    
    def getIssueBackground(self):
        return "JavaScript files may contain hardcoded credentials, API keys, tokens, or other sensitive information."
    
    def getRemediationBackground(self):
        return "Remove sensitive data from client-side code. Use environment variables, secure storage, or server-side APIs."
    
    def getIssueDetail(self):
        detail = "Sensitive data found in JS file: <b>%s</b><br><br>" % self.reqres.getUrl().toString()
        detail += "<b>Findings:</b><ul>"
        for finding in self.findings[:10]:  # Limitar a 10 para no sobrecargar
            detail += "<li><b>%s</b> (%s): %s</li>" % (
                finding['type'], 
                finding['severity'], 
                self.helpers.urlEncode(finding['value'][:100])
            )
        if len(self.findings) > 10:
            detail += "<li>... and %d more</li>" % (len(self.findings) - 10)
        detail += "</ul>"
        return detail
    
    def getRemediationDetail(self):
        return None
    
    def getHttpMessages(self):
        return [self.reqres]
    
    def getHttpService(self):
        return self.reqres.getHttpService()


class SRI(IScanIssue,ITab):
    def __init__(self, reqres, helpers, endpoints):
        self.helpers = helpers
        self.reqres = reqres
        self.endpoints = endpoints or []

    def getHost(self):
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        return "Linkfinder Analysed JS files"

    def getIssueType(self):
        return 0x08000000  # See http:#portswigger.net/burp/help/scanner_issuetypes.html

    def getSeverity(self):
        return "Information"  # "High", "Medium", "Low", "Information" or "False positive"

    def getConfidence(self):
        return "Certain"  # "Certain", "Firm" or "Tentative"

    def getIssueBackground(self):
        return str("JS files holds links to other parts of web applications. Refer to TAB for results.")

    def getRemediationBackground(self):
        return "This is an <b>informational</b> finding only.<br>"

    def getIssueDetail(self):
        detail = ("Burp Scanner has analysed the following JS file for links: <b>"
                      "%s</b><br><br>" % (self.reqres.getUrl().toString()))
        if not self.endpoints:
            return detail + "No endpoints were extracted for this response."

        detail += "<b>Sample endpoints found:</b><ul>"
        for endpoint in self.endpoints[:MAX_ISSUE_ENDPOINTS]:
            detail += "<li>%s</li>" % escape_html(endpoint['link'][:200])
        if len(self.endpoints) > MAX_ISSUE_ENDPOINTS:
            detail += "<li>... and %d more</li>" % (len(self.endpoints) - MAX_ISSUE_ENDPOINTS)
        detail += "</ul>"
        return detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        #print ("................raising issue................")
        rra = [self.reqres]
        return rra
        
    def getHttpService(self):
        return self.reqres.getHttpService()
