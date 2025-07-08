package com.apisecurity;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import burp.api.montoya.logging.Logging;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class ApiSecurityTester implements BurpExtension, ProxyRequestHandler, ProxyResponseHandler {
    
    private MontoyaApi api;
    private Logging logging;
    private JPanel mainPanel;
    private JTextArea outputArea;
    private JCheckBox enableTokenDiscovery;
    private JCheckBox enableCorsCheck;
    private JCheckBox enableAuthTest;
    private List<TokenFinding> tokenFindings;
    
    // Token patterns for discovery
    private static final Map<String, Pattern> TOKEN_PATTERNS = new HashMap<>();
    static {
        TOKEN_PATTERNS.put("JWT", Pattern.compile("eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"));
        TOKEN_PATTERNS.put("API Key", Pattern.compile("(?i)[aA][pP][iI][_-]?[kK][eE][yY][_-]?[:\\s=][\\s]*['\"]?([A-Za-z0-9_-]{20,})['\"]?"));
        TOKEN_PATTERNS.put("Bearer", Pattern.compile("(?i)[bB][eE][aA][rR][eE][rR][\\s]+([A-Za-z0-9_-]{20,})"));
        TOKEN_PATTERNS.put("GitHub", Pattern.compile("gh[pousr]_[A-Za-z0-9_]{36}"));
        TOKEN_PATTERNS.put("Slack", Pattern.compile("xox[baprs]-[A-Za-z0-9_-]{10,}"));
        TOKEN_PATTERNS.put("AWS Access", Pattern.compile("AKIA[0-9A-Z]{16}"));
        TOKEN_PATTERNS.put("Generic Secret", Pattern.compile("(?i)[sS][eE][cC][rR][eE][tT][_-]?[:\\s=][\\s]*['\"]?([A-Za-z0-9_-]{20,})['\"]?"));
    }
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.tokenFindings = new ArrayList<>();
        
        // Set extension name
        api.extension().setName("API Security Tester");
        
        // Create UI
        createUI();
        
        // Register handlers
        api.proxy().registerRequestHandler(this);
        api.proxy().registerResponseHandler(this);
        
        logging.logToOutput("API Security Tester loaded successfully");
    }
    
    private void createUI() {
        mainPanel = new JPanel(new BorderLayout());
        
        // Settings panel
        JPanel settingsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        settingsPanel.setBorder(BorderFactory.createTitledBorder("Settings"));
        
        enableTokenDiscovery = new JCheckBox("Token Discovery", true);
        enableCorsCheck = new JCheckBox("CORS Check", true);
        enableAuthTest = new JCheckBox("Auth Testing", true);
        
        JButton clearButton = new JButton("Clear Results");
        clearButton.addActionListener(e -> clearResults());
        
        JButton scanButton = new JButton("Manual Scan");
        scanButton.addActionListener(e -> performManualScan());
        
        settingsPanel.add(enableTokenDiscovery);
        settingsPanel.add(enableCorsCheck);
        settingsPanel.add(enableAuthTest);
        settingsPanel.add(clearButton);
        settingsPanel.add(scanButton);
        
        // Output area
        outputArea = new JTextArea(20, 80);
        outputArea.setEditable(false);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(outputArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Security Findings"));
        
        mainPanel.add(settingsPanel, BorderLayout.NORTH);
        mainPanel.add(scrollPane, BorderLayout.CENTER);
        
        // Add to Burp UI
        api.userInterface().registerSuiteTab("API Security", mainPanel);
    }
    
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }
    
    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        if (enableTokenDiscovery.isSelected()) {
            analyzeRequestForTokens(interceptedRequest);
        }
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }
    
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        if (enableTokenDiscovery.isSelected()) {
            analyzeResponseForTokens(interceptedResponse);
        }
        
        if (enableCorsCheck.isSelected()) {
            checkCorsHeaders(interceptedResponse);
        }
        
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }
    
    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
    
    private void analyzeRequestForTokens(InterceptedRequest request) {
        String requestData = request.toString();
        String url = request.url();
        
        findTokensInText(requestData, "Request to " + url);
        
        // Check headers specifically
        request.headers().forEach(header -> {
            if (header.name().toLowerCase().contains("authorization") || 
                header.name().toLowerCase().contains("token") ||
                header.name().toLowerCase().contains("key")) {
                findTokensInText(header.value(), "Request header: " + header.name());
            }
        });
    }
    
    private void analyzeResponseForTokens(InterceptedResponse response) {
        String responseData = response.toString();
        String url = response.initiatingRequest().url();
        
        findTokensInText(responseData, "Response from " + url);
        
        // Check response headers
        response.headers().forEach(header -> {
            if (header.name().toLowerCase().contains("authorization") || 
                header.name().toLowerCase().contains("token") ||
                header.name().toLowerCase().contains("key")) {
                findTokensInText(header.value(), "Response header: " + header.name());
            }
        });
    }
    
    private void findTokensInText(String text, String source) {
        for (Map.Entry<String, Pattern> entry : TOKEN_PATTERNS.entrySet()) {
            String tokenType = entry.getKey();
            Pattern pattern = entry.getValue();
            Matcher matcher = pattern.matcher(text);
            
            while (matcher.find()) {
                String token = matcher.group();
                if (token.length() > 15) { // Minimum token length
                    TokenFinding finding = new TokenFinding(tokenType, token, source);
                    
                    // Avoid duplicates
                    if (!tokenFindings.contains(finding)) {
                        tokenFindings.add(finding);
                        logTokenFinding(finding);
                    }
                }
            }
        }
    }
    
    private void checkCorsHeaders(InterceptedResponse response) {
        String corsHeader = response.headerValue("Access-Control-Allow-Origin");
        if (corsHeader != null) {
            if ("*".equals(corsHeader)) {
                String message = "[!] CORS VULNERABILITY: Wildcard CORS header found at " + 
                               response.initiatingRequest().url();
                appendToOutput(message);
                logging.logToOutput(message);
            } else if (corsHeader.contains("null")) {
                String message = "[!] CORS ISSUE: Null origin allowed at " + 
                               response.initiatingRequest().url();
                appendToOutput(message);
            }
        }
    }
    
    private void logTokenFinding(TokenFinding finding) {
        String message = String.format("[!] TOKEN FOUND: %s token discovered in %s\n    Token: %s...", 
                                     finding.getType(), 
                                     finding.getSource(), 
                                     finding.getToken().substring(0, Math.min(20, finding.getToken().length())));
        appendToOutput(message);
        logging.logToOutput(message);
    }
    
    private void appendToOutput(String message) {
        SwingUtilities.invokeLater(() -> {
            outputArea.append(message + "\n");
            outputArea.setCaretPosition(outputArea.getDocument().getLength());
        });
    }
    
    private void clearResults() {
        tokenFindings.clear();
        outputArea.setText("");
        logging.logToOutput("Results cleared");
    }
    
    private void performManualScan() {
        appendToOutput("=== Manual Security Scan Started ===");
        
        // Get current HTTP history
        List<HttpRequestResponse> history = api.proxy().history();
        
        for (HttpRequestResponse item : history) {
            HttpRequest request = item.request();
            HttpResponse response = item.response();
            
            if (response != null) {
                // Analyze for tokens
                if (enableTokenDiscovery.isSelected()) {
                    findTokensInText(request.toString(), "Manual scan - Request to " + request.url());
                    findTokensInText(response.toString(), "Manual scan - Response from " + request.url());
                }
                
                // Check CORS
                if (enableCorsCheck.isSelected()) {
                    String corsHeader = response.headerValue("Access-Control-Allow-Origin");
                    if (corsHeader != null && "*".equals(corsHeader)) {
                        appendToOutput("[!] CORS VULNERABILITY: Wildcard CORS at " + request.url());
                    }
                }
            }
        }
        
        appendToOutput("=== Manual Scan Complete ===");
        appendToOutput("Total tokens found: " + tokenFindings.size());
    }
    
    // Token finding data class
    private static class TokenFinding {
        private final String type;
        private final String token;
        private final String source;
        
        public TokenFinding(String type, String token, String source) {
            this.type = type;
            this.token = token;
            this.source = source;
        }
        
        public String getType() { return type; }
        public String getToken() { return token; }
        public String getSource() { return source; }
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;
            TokenFinding that = (TokenFinding) obj;
            return token.equals(that.token) && source.equals(that.source);
        }
        
        @Override
        public int hashCode() {
            return token.hashCode() + source.hashCode();
        }
    }
}