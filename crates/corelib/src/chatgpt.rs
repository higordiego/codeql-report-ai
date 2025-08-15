use crate::{
    config::Config,
    error::CodeQLError,
    types::{ChatMessage, ChatRequest, ChatResponse},
};
use reqwest::Client;
use std::time::Duration;
use tracing::error;

/// Client for interacting with ChatGPT API
pub struct ChatGPTClient {
    config: Config,
    client: Client,
}

impl ChatGPTClient {
    /// Creates a new ChatGPT client with the given configuration
    pub fn new(config: &Config) -> crate::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .map_err(|e| {
                CodeQLError::NetworkError(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self {
            config: config.clone(),
            client,
        })
    }

    /// Sends a request to the ChatGPT API
    async fn send_request(&self, messages: Vec<ChatMessage>) -> crate::Result<String> {
        let request_body = ChatRequest {
            model: self.config.model.clone(),
            messages,
            temperature: self.config.temperature,
            max_tokens: 4000,
        };

        let response = self
            .client
            .post(&self.config.openai_base_url)
            .header(
                "Authorization",
                format!("Bearer {}", self.config.openai_api_key),
            )
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| CodeQLError::NetworkError(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!("ChatGPT API error: {}", error_text);
            return Err(CodeQLError::ApiError(format!(
                "ChatGPT API error: {}",
                error_text
            )));
        }

        let chat_response: ChatResponse = response
            .json()
            .await
            .map_err(|e| CodeQLError::JsonParseError(format!("Failed to parse response: {}", e)))?;

        if let Some(choice) = chat_response.choices.first() {
            if let Some(message) = &choice.message {
                Ok(message.content.clone())
            } else {
                Err(CodeQLError::ApiError(
                    "No message content in response".to_string(),
                ))
            }
        } else {
            Err(CodeQLError::ApiError("No choices in response".to_string()))
        }
    }

    /// Generates a medium-level report using ChatGPT
    pub async fn generate_medium_report(
        &self,
        _findings: &[crate::types::CodeQLResult],
        code_snippets: &[(String, String)],
        full_file_content: &str,
        original_json: &str,
    ) -> crate::Result<String> {
        let system_message = ChatMessage {
            role: "system".to_string(),
            content: self.get_medium_report_system_prompt().to_string(),
        };

        let user_message = ChatMessage {
            role: "user".to_string(),
            content: format!(
                r#"Analyze the following CodeQL JSON and code file to generate a detailed security report.

CodeQL Results JSON:
{}

Full File Content:
{}

Code Snippets from Problematic Lines:
{}

Please generate a comprehensive security report that includes:
1. Executive Summary
2. Statistics by severity and rule type
3. Detailed analysis of each finding
4. Code snippets showing the problematic lines
5. Security implications and risks
6. Recommendations for fixing each vulnerability

Format the report in Markdown with clear sections and code blocks."#,
                original_json,
                full_file_content,
                self.format_code_snippets(code_snippets)
            ),
        };

        let messages = vec![system_message, user_message];
        let response = self.send_request(messages).await?;
        Ok(response)
    }

    /// Generates an advanced report with correction recommendations using ChatGPT
    pub async fn generate_advanced_report(
        &self,
        _findings: &[crate::types::CodeQLResult],
        code_snippets: &[(String, String)],
        full_file_content: &str,
        original_json: &str,
    ) -> crate::Result<String> {
        let system_message = ChatMessage {
            role: "system".to_string(),
            content: self.get_advanced_report_system_prompt().to_string(),
        };

        let user_message = ChatMessage {
            role: "user".to_string(),
            content: format!(
                r#"Analyze the following CodeQL JSON and code file to generate an advanced security report with correction recommendations.

CodeQL Results JSON:
{}

Full File Content:
{}

Code Snippets from Problematic Lines:
{}

Please generate a comprehensive security report that includes:
1. Executive Summary
2. Statistics by severity and rule type
3. Detailed analysis of each finding
4. Code snippets showing the problematic lines
5. Security implications and risks
6. Specific correction recommendations for each vulnerability
7. Code examples showing how to fix each issue
8. General security best practices

Format the report in Markdown with clear sections, code blocks, and actionable recommendations."#,
                original_json,
                full_file_content,
                self.format_code_snippets(code_snippets)
            ),
        };

        let messages = vec![system_message, user_message];
        let response = self.send_request(messages).await?;
        Ok(response)
    }

    /// Generates corrected code based on found vulnerabilities
    pub async fn generate_fixed_code(
        &self,
        _findings: &[crate::types::CodeQLResult],
        _code_snippets: &[(String, String)],
        full_file_content: &str,
        original_json: &str,
    ) -> crate::Result<String> {
        let system_message = ChatMessage {
            role: "system".to_string(),
            content: self.get_code_fix_system_prompt().to_string(),
        };

        let user_message = ChatMessage {
            role: "user".to_string(),
            content: format!(
                r#"Analyze the following CodeQL JSON and code file to generate corrected and secure code.

CodeQL Results JSON:
{}

Full File Content:
{}

Please generate corrected code that:
1. Addresses all security vulnerabilities identified in the CodeQL results
2. Implements proper input validation
3. Uses secure coding practices
4. Includes logging for audit purposes
5. Handles exceptions properly
6. Maintains the original functionality while being secure

Return ONLY the corrected Python code without any explanations or markdown formatting."#,
                original_json, full_file_content
            ),
        };

        let messages = vec![system_message, user_message];
        let response = self.send_request(messages).await?;
        Ok(response)
    }

    /// Gets the system prompt for medium-level reports
    fn get_medium_report_system_prompt(&self) -> &str {
        r#"You are a cybersecurity expert and code analysis specialist. Your task is to analyze CodeQL static analysis results and generate comprehensive security reports.

Key Responsibilities:
- Analyze security vulnerabilities in code
- Provide detailed explanations of security risks
- Generate professional security reports
- Include relevant code snippets and context
- Explain the impact and severity of findings

Report Format Requirements:
- Use Markdown formatting
- Include clear section headers
- Provide code blocks for code snippets
- Use bullet points for lists
- Include severity indicators
- Group findings by type when appropriate

Security Focus Areas:
- Command injection vulnerabilities
- SQL injection issues
- Path traversal problems
- Cross-site scripting (XSS)
- Unsafe deserialization
- Hardcoded secrets
- Input validation issues

Response Guidelines:
- Be professional and technical
- Provide actionable insights
- Include security context
- Explain potential impacts
- Suggest general remediation approaches
- Maintain objectivity and accuracy"#
    }

    /// Gets the system prompt for advanced reports
    fn get_advanced_report_system_prompt(&self) -> &str {
        r#"You are a senior cybersecurity expert and secure coding specialist. Your task is to analyze CodeQL static analysis results and generate advanced security reports with specific correction recommendations.

Key Responsibilities:
- Analyze security vulnerabilities in code
- Provide detailed explanations of security risks
- Generate professional security reports with specific fixes
- Include relevant code snippets and context
- Explain the impact and severity of findings
- Provide specific code correction examples

Report Format Requirements:
- Use Markdown formatting
- Include clear section headers
- Provide code blocks for code snippets
- Use bullet points for lists
- Include severity indicators
- Group findings by type when appropriate
- Include "Correction Recommendation" section for each finding
- Include "Correction Recommendations" general section

Security Focus Areas:
- Command injection vulnerabilities
- SQL injection issues
- Path traversal problems
- Cross-site scripting (XSS)
- Unsafe deserialization
- Hardcoded secrets
- Input validation issues

Correction Guidelines:
- Provide specific code examples for fixes
- Explain why the fix works
- Include input validation examples
- Show secure coding patterns
- Demonstrate proper error handling
- Include logging and audit considerations

Response Guidelines:
- Be professional and technical
- Provide actionable insights with specific code
- Include security context and explanations
- Explain potential impacts and risks
- Provide detailed remediation approaches
- Include code examples for each fix
- Maintain objectivity and accuracy"#
    }

    /// Gets the system prompt for code correction
    fn get_code_fix_system_prompt(&self) -> &str {
        r#"You are a security and Python development expert. Your task is to analyze security vulnerabilities identified by CodeQL and generate corrected and secure code.

Key Responsibilities:
- Analyze security vulnerabilities in the provided code
- Generate corrected code that addresses all identified issues
- Implement security best practices
- Maintain original functionality while improving security

Security Requirements:
- Implement proper input validation
- Use secure command execution (subprocess.run with shell=False)
- Add input sanitization
- Include logging for audit purposes
- Handle exceptions properly
- Use parameterized queries for database operations
- Validate file paths and prevent path traversal
- Implement proper error handling without information disclosure

Code Generation Rules:
- Return ONLY the corrected Python code
- Do not include any explanations, comments, or markdown
- Maintain the original function structure and purpose
- Add necessary imports for security features
- Include logging configuration
- Add input validation functions
- Use secure coding patterns
- Include timeout mechanisms for external operations

Security Patterns to Implement:
- Input validation with regex patterns
- Command allowlist for subprocess operations
- Path validation and sanitization
- Exception handling with proper logging
- Timeout mechanisms for external calls
- Secure file operations
- Parameterized database queries

Response Format:
- Return ONLY the corrected Python code
- No explanations, comments, or markdown formatting
- Complete, executable Python code
- Include all necessary imports and functions"#
    }

    /// Formats code snippets for inclusion in prompts
    fn format_code_snippets(&self, code_snippets: &[(String, String)]) -> String {
        let mut formatted = String::new();
        for (file_path, snippet) in code_snippets {
            formatted.push_str(&format!("File: {}\n", file_path));
            formatted.push_str("```python\n");
            formatted.push_str(snippet);
            formatted.push_str("\n```\n\n");
        }
        formatted
    }
}
