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
        // Verifica se a mensagem é muito grande
        let total_tokens = self.estimate_tokens(&messages);
        if total_tokens > 12000 {
            // Deixa margem de segurança
            return Err(CodeQLError::ApiError(format!(
                "Content too large: {} tokens (max: 12000)",
                total_tokens
            )));
        }

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

    /// Estimates the number of tokens in a message (rough approximation)
    fn estimate_tokens(&self, messages: &[ChatMessage]) -> usize {
        let mut total_chars = 0;
        for message in messages {
            total_chars += message.content.len();
        }
        // Aproximação: 1 token ≈ 4 caracteres
        total_chars / 4
    }

    /// Splits content into smaller chunks for processing
    fn split_content(&self, content: &str, max_chars: usize) -> Vec<String> {
        let mut chunks = Vec::new();
        let mut current_chunk = String::new();

        for line in content.lines() {
            if current_chunk.len() + line.len() + 1 > max_chars {
                if !current_chunk.is_empty() {
                    chunks.push(current_chunk);
                    current_chunk = String::new();
                }
            }
            if !current_chunk.is_empty() {
                current_chunk.push('\n');
            }
            current_chunk.push_str(line);
        }

        if !current_chunk.is_empty() {
            chunks.push(current_chunk);
        }

        chunks
    }

    /// Extracts only the "results" section from SARIF JSON
    fn extract_results_only(&self, sarif_json: &str) -> crate::Result<String> {
        use serde_json::Value;

        let json_value: Value = serde_json::from_str(sarif_json)
            .map_err(|e| crate::error::CodeQLError::JsonParseError(e.to_string()))?;

        // Extrai apenas a seção "results" de cada "run"
        if let Some(runs) = json_value.get("runs").and_then(|r| r.as_array()) {
            let mut all_results = Vec::new();

            for run in runs {
                if let Some(results) = run.get("results").and_then(|r| r.as_array()) {
                    for result in results {
                        all_results.push(result.clone());
                    }
                }
            }

            // Cria um JSON simplificado apenas com os resultados
            let results_json = serde_json::json!({
                "results": all_results
            });

            Ok(serde_json::to_string_pretty(&results_json)
                .map_err(|e| crate::error::CodeQLError::JsonParseError(e.to_string()))?)
        } else {
            Err(crate::error::CodeQLError::JsonParseError(
                "Não foi possível encontrar a seção 'runs' no JSON SARIF".to_string(),
            ))
        }
    }

    /// Generates a medium-level report using ChatGPT
    pub async fn generate_medium_report(
        &self,
        _findings: &[crate::types::CodeQLResult],
        code_snippets: &[(String, String)],
        _full_file_content: &str,
        original_json: &str,
    ) -> crate::Result<String> {
        // Extrai apenas os resultados do JSON SARIF
        let results_only = self.extract_results_only(original_json)?;

        // Divide o conteúdo em chunks menores
        let max_chars = 8000; // Limite conservador para evitar exceder tokens
        let json_chunks = self.split_content(&results_only, max_chars);

        let mut all_responses = Vec::new();

        // Processa cada chunk do JSON
        for (i, json_chunk) in json_chunks.iter().enumerate() {
            let system_message = ChatMessage {
                role: "system".to_string(),
                content: self.get_medium_report_system_prompt().to_string(),
            };

            let user_message = ChatMessage {
                role: "user".to_string(),
                content: format!(
                    r#"Analise o seguinte JSON do CodeQL (parte {}/{}).

JSON dos Resultados do CodeQL:
{}

Trechos de Código das Linhas Problemáticas:
{}

Por favor, gere um relatório de segurança para esta parte que inclua:
1. Análise das descobertas nesta seção
2. Trechos de código relevantes
3. Implicações de segurança
4. Recomendações específicas

Formate em Markdown."#,
                    i + 1,
                    json_chunks.len(),
                    json_chunk,
                    self.format_code_snippets(code_snippets)
                ),
            };

            let messages = vec![system_message, user_message];
            let response = self.send_request(messages).await?;
            all_responses.push(response);
        }

        // Combina todas as respostas
        Ok(all_responses.join("\n\n---\n\n"))
    }

    /// Generates an advanced report with correction recommendations using ChatGPT
    pub async fn generate_advanced_report(
        &self,
        _findings: &[crate::types::CodeQLResult],
        code_snippets: &[(String, String)],
        _full_file_content: &str,
        original_json: &str,
    ) -> crate::Result<String> {
        // Extrai apenas os resultados do JSON SARIF
        let results_only = self.extract_results_only(original_json)?;

        // Divide o conteúdo em chunks menores
        let max_chars = 8000; // Limite conservador para evitar exceder tokens
        let json_chunks = self.split_content(&results_only, max_chars);

        let mut all_responses = Vec::new();

        // Processa cada chunk do JSON
        for (i, json_chunk) in json_chunks.iter().enumerate() {
            let system_message = ChatMessage {
                role: "system".to_string(),
                content: self.get_advanced_report_system_prompt().to_string(),
            };

            let user_message = ChatMessage {
                role: "user".to_string(),
                content: format!(
                    r#"Analise o seguinte JSON do CodeQL (parte {}/{}).

JSON dos Resultados do CodeQL:
{}

Trechos de Código das Linhas Problemáticas:
{}

Por favor, gere um relatório de segurança avançado para esta parte que inclua:
1. Análise detalhada das descobertas
2. Trechos de código relevantes
3. Implicações de segurança e riscos
4. Recomendações específicas de correção
5. Exemplos de código corrigido
6. Melhores práticas de segurança

Formate em Markdown com blocos de código."#,
                    i + 1,
                    json_chunks.len(),
                    json_chunk,
                    self.format_code_snippets(code_snippets)
                ),
            };

            let messages = vec![system_message, user_message];
            let response = self.send_request(messages).await?;
            all_responses.push(response);
        }

        // Combina todas as respostas
        Ok(all_responses.join("\n\n---\n\n"))
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

        // Extrai apenas os resultados do JSON SARIF
        let results_only = self.extract_results_only(original_json)?;

        // Divide o conteúdo em chunks menores
        let max_chars = 8000; // Limite conservador para evitar exceder tokens
        let json_chunks = self.split_content(&results_only, max_chars);

        let mut all_responses = Vec::new();

        // Processa cada chunk do JSON
        for (i, json_chunk) in json_chunks.iter().enumerate() {
            let user_message = ChatMessage {
                role: "user".to_string(),
                content: format!(
                    r#"Analise o seguinte JSON do CodeQL (parte {}/{}).

JSON dos Resultados do CodeQL:
{}

Conteúdo do Arquivo:
{}

Por favor, gere código corrigido que:
1. Aborde as vulnerabilidades de segurança identificadas nesta seção
2. Implemente validação adequada de entrada
3. Use práticas seguras de codificação
4. Inclua logging para fins de auditoria
5. Trate exceções adequadamente

IMPORTANTE: Retorne APENAS o código Python corrigido como texto puro.
NÃO use formatação markdown (sem ```python ou ```).
NÃO inclua explicações ou comentários.
Comece diretamente com os imports e termine com a última linha de código."#,
                    i + 1,
                    json_chunks.len(),
                    json_chunk,
                    full_file_content
                ),
            };

            let messages = vec![system_message.clone(), user_message];
            let response = self.send_request(messages).await?;
            all_responses.push(response);
        }

        // Combina todas as respostas e remove formatação markdown se presente
        let combined_response = all_responses.join("\n\n");
        let cleaned_response = self.clean_markdown_formatting(&combined_response);
        Ok(cleaned_response)
    }

    /// Removes markdown formatting from ChatGPT response
    fn clean_markdown_formatting(&self, response: &str) -> String {
        let mut cleaned = response.to_string();

        // Remove ```python and ``` blocks
        cleaned = cleaned.replace("```python", "").replace("```", "");

        // Remove leading/trailing whitespace
        cleaned = cleaned.trim().to_string();

        cleaned
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
- Do not include any explanations, comments, or markdown formatting
- Do NOT use ```python or ``` markdown blocks
- Do NOT include any markdown syntax
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
- Return ONLY the corrected Python code as plain text
- NO markdown formatting (no ```python, no ```)
- NO explanations or comments
- Complete, executable Python code
- Include all necessary imports and functions
- Start directly with the Python code (import statements)
- End with the last line of Python code
- DO NOT include any markdown syntax whatsoever
- DO NOT use code blocks or backticks
- Return raw Python code only"#
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
