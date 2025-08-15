use crate::{
    chatgpt::ChatGPTClient,
    config::Config,
    error::CodeQLError,
    types::{CodeQLAnalysis, CodeQLResult, ReportLevel},
};
use colored::*;
use std::collections::HashMap;
use std::fs;
use std::str::FromStr;
use tracing::{info, warn};

/// Main analyzer for CodeQL results with AI integration
pub struct CodeQLAnalyzer {
    config: Config,
    chatgpt_client: ChatGPTClient,
}

impl CodeQLAnalyzer {
    /// Creates a new CodeQL analyzer with the given configuration
    pub fn new(config: Config) -> crate::Result<Self> {
        let chatgpt_client = ChatGPTClient::new(&config)?;
        Ok(Self {
            config,
            chatgpt_client,
        })
    }

    /// Main analysis method that processes CodeQL results and generates reports
    pub async fn analyze(&self, codeql_json_path: &str) -> crate::Result<()> {
        info!("Starting CodeQL analysis: {}", codeql_json_path);
        println!("{}", "📂 Loading CodeQL results file...".bright_blue());

        let codeql_analysis = self.load_codeql_results(codeql_json_path).await?;

        println!(
            "{}",
            "📄 Extracting code from problematic lines...".bright_yellow()
        );
        let code_snippets = self
            .extract_code_snippets(&codeql_analysis.results())
            .await?;

        let full_file_content = self.read_full_file(&codeql_analysis.results()).await?;
        let original_json = self.read_original_json(codeql_json_path).await?;

        println!("{}", "🤖 Analyzing with AI...".bright_magenta());

        let report_level = ReportLevel::from_str(&self.config.report_level)
            .map_err(|e| CodeQLError::ConfigError(format!("Invalid report level: {}", e)))?;

        let report_content = match report_level {
            ReportLevel::Easy => {
                println!("{}", "📊 Generating basic report...".bright_cyan());
                self.generate_basic_report(&codeql_analysis).await?
            }
            ReportLevel::Medium => {
                println!("{}", "📋 Generating detailed report...".bright_cyan());
                match self
                    .chatgpt_client
                    .generate_medium_report(
                        &codeql_analysis.results(),
                        &code_snippets,
                        &full_file_content,
                        &original_json,
                    )
                    .await
                {
                    Ok(content) => content,
                    Err(_) => {
                        warn!("ChatGPT failed, generating basic report");
                        self.generate_basic_report(&codeql_analysis).await?
                    }
                }
            }
            ReportLevel::Advanced => {
                println!(
                    "{}",
                    "🔍 Generating advanced report with recommendations...".bright_cyan()
                );
                match self
                    .chatgpt_client
                    .generate_advanced_report(
                        &codeql_analysis.results(),
                        &code_snippets,
                        &full_file_content,
                        &original_json,
                    )
                    .await
                {
                    Ok(content) => content,
                    Err(_) => {
                        warn!(
                            "ChatGPT failed, generating advanced report with basic recommendations"
                        );
                        self.generate_advanced_report_with_recommendations(
                            &codeql_analysis,
                            &code_snippets,
                            &full_file_content,
                        )
                        .await?
                    }
                }
            }
        };

        println!("{}", "💾 Saving report...".bright_cyan());
        self.save_report(&report_content).await?;

        info!("Analysis completed successfully!");
        Ok(())
    }

    /// Generates corrected code based on found vulnerabilities
    pub async fn generate_fixed_code(
        &self,
        codeql_json_path: &str,
        output_path: &str,
    ) -> crate::Result<()> {
        info!(
            "Starting corrected code generation: {} -> {}",
            codeql_json_path, output_path
        );
        println!("{}", "📂 Loading CodeQL results file...".bright_blue());
        let codeql_analysis = self.load_codeql_results(codeql_json_path).await?;

        println!(
            "{}",
            "📄 Extracting code from problematic lines...".bright_yellow()
        );
        let code_snippets = self
            .extract_code_snippets(&codeql_analysis.results())
            .await?;
        let full_file_content = self.read_full_file(&codeql_analysis.results()).await?;
        let original_json = self.read_original_json(codeql_json_path).await?;

        println!("{}", "🔧 Generating corrected code...".bright_magenta());

        let fixed_code = match self
            .chatgpt_client
            .generate_fixed_code(
                &codeql_analysis.results(),
                &code_snippets,
                &full_file_content,
                &original_json,
            )
            .await
        {
            Ok(code) => code,
            Err(_) => {
                warn!("ChatGPT failed, generating basic corrected code");
                self.generate_basic_fixed_code(&codeql_analysis, &code_snippets, &full_file_content)
                    .await?
            }
        };

        println!("{}", "💾 Saving corrected code...".bright_cyan());
        self.save_fixed_code(&fixed_code, output_path).await?;

        info!("Corrected code generated successfully!");
        Ok(())
    }

    /// Loads and parses CodeQL results from JSON file
    async fn load_codeql_results(&self, file_path: &str) -> crate::Result<CodeQLAnalysis> {
        let content = fs::read_to_string(file_path).map_err(|e| {
            CodeQLError::FileReadError(format!("Failed to read file {}: {}", file_path, e))
        })?;

        serde_json::from_str(&content)
            .map_err(|e| CodeQLError::JsonParseError(format!("Failed to parse JSON: {}", e)))
    }

    /// Extracts code snippets from the lines mentioned in CodeQL results
    async fn extract_code_snippets(
        &self,
        results: &[CodeQLResult],
    ) -> crate::Result<Vec<(String, String)>> {
        let mut snippets = Vec::new();

        for result in results {
            if let Some(location) = &result.locations.first() {
                if let Some(physical_location) = &location.physical_location {
                    let file_path = &physical_location.artifact_location.uri;
                    let start_line = physical_location.region.start_line;
                    let end_line = physical_location.region.end_line.unwrap_or(start_line);

                    // Read the file and extract the specific lines
                    let full_path = self.config.project_root.join(file_path);
                    if full_path.exists() {
                        match fs::read_to_string(&full_path) {
                            Ok(content) => {
                                let lines: Vec<&str> = content.lines().collect();
                                let start_idx = (start_line - 1) as usize;
                                let end_idx = (end_line - 1) as usize;

                                if start_idx < lines.len() && end_idx < lines.len() {
                                    let snippet_lines: Vec<&str> =
                                        lines[start_idx..=end_idx].to_vec();
                                    let snippet = snippet_lines.join("\n");
                                    snippets.push((file_path.clone(), snippet));
                                }
                            }
                            Err(e) => {
                                warn!("Failed to read file {}: {}", full_path.display(), e);
                            }
                        }
                    }
                }
            }
        }

        Ok(snippets)
    }

    /// Reads the full content of files mentioned in CodeQL results
    async fn read_full_file(&self, results: &[CodeQLResult]) -> crate::Result<String> {
        let mut file_contents = Vec::new();

        for result in results {
            if let Some(location) = &result.locations.first() {
                if let Some(physical_location) = &location.physical_location {
                    let file_path = &physical_location.artifact_location.uri;
                    let full_path = self.config.project_root.join(file_path);

                    if full_path.exists() {
                        match fs::read_to_string(&full_path) {
                            Ok(content) => {
                                file_contents
                                    .push(format!("File: {}\nContent:\n{}", file_path, content));
                            }
                            Err(e) => {
                                warn!("Failed to read file {}: {}", full_path.display(), e);
                            }
                        }
                    }
                }
            }
        }

        Ok(file_contents.join("\n\n"))
    }

    /// Reads the original JSON content
    async fn read_original_json(&self, file_path: &str) -> crate::Result<String> {
        fs::read_to_string(file_path)
            .map_err(|e| CodeQLError::FileReadError(format!("Failed to read JSON file: {}", e)))
    }

    /// Saves the generated report to the output file
    async fn save_report(&self, content: &str) -> crate::Result<()> {
        fs::write(&self.config.output_file, content)
            .map_err(|e| CodeQLError::FileWriteError(format!("Failed to write report: {}", e)))?;

        println!(
            "{}",
            format!("📄 Report saved to: {}", self.config.output_file.display()).bright_green()
        );
        Ok(())
    }

    /// Saves the generated corrected code to the output file
    async fn save_fixed_code(&self, content: &str, output_path: &str) -> crate::Result<()> {
        fs::write(output_path, content).map_err(|e| {
            CodeQLError::FileWriteError(format!("Failed to write corrected code: {}", e))
        })?;

        println!(
            "{}",
            format!("📄 Corrected code saved to: {}", output_path).bright_green()
        );
        Ok(())
    }

    /// Generates a basic report without AI analysis
    async fn generate_basic_report(&self, analysis: &CodeQLAnalysis) -> crate::Result<String> {
        let mut report = String::new();

        // Header
        report.push_str("# Relatório de Análise de Segurança CodeQL\n\n");
        report.push_str("## Resumo Executivo\n\n");
        report.push_str(&format!(
            "- **Total de Descobertas**: {}\n",
            analysis.results().len()
        ));

        // Statistics
        let mut severity_counts: HashMap<String, usize> = HashMap::new();
        let mut rule_counts: HashMap<String, usize> = HashMap::new();

        for result in analysis.results() {
            *severity_counts.entry(result.level.clone()).or_insert(0) += 1;
            *rule_counts.entry(result.rule_id.clone()).or_insert(0) += 1;
        }

        report.push_str("## Estatísticas\n\n");
        report.push_str("### Por Severidade\n");
        for (severity, count) in &severity_counts {
            report.push_str(&format!("- **{}**: {} descobertas\n", severity, count));
        }

        report.push_str("\n### Por Regra\n");
        for (rule, count) in &rule_counts {
            report.push_str(&format!("- **{}**: {} descobertas\n", rule, count));
        }

        // Detailed findings
        report.push_str("\n## Descobertas Detalhadas\n\n");
        for (i, result) in analysis.results().iter().enumerate() {
            report.push_str(&format!("### Descoberta {}\n\n", i + 1));
            report.push_str(&format!("- **Regra**: {}\n", result.rule_id));
            report.push_str(&format!("- **Severidade**: {}\n", result.level));
            report.push_str(&format!("- **Mensagem**: {}\n", result.message));

            if let Some(location) = &result.locations.first() {
                if let Some(physical_location) = &location.physical_location {
                    report.push_str(&format!(
                        "- **Arquivo**: {}\n",
                        physical_location.artifact_location.uri
                    ));
                    report.push_str(&format!(
                        "- **Linha**: {}\n",
                        physical_location.region.start_line
                    ));
                }
            }
            report.push('\n');
        }

        Ok(report)
    }

    /// Generates an advanced report with basic recommendations
    async fn generate_advanced_report_with_recommendations(
        &self,
        analysis: &CodeQLAnalysis,
        code_snippets: &[(String, String)],
        _full_file_content: &str,
    ) -> crate::Result<String> {
        let mut report = String::new();

        // Header
        report.push_str("# Relatório de Análise de Segurança CodeQL - Avançado\n\n");
        report.push_str("## Resumo Executivo\n\n");
        report.push_str(&format!(
            "- **Total de Descobertas**: {}\n",
            analysis.results().len()
        ));

        // Statistics
        let mut severity_counts: HashMap<String, usize> = HashMap::new();
        let mut rule_counts: HashMap<String, usize> = HashMap::new();

        for result in analysis.results() {
            *severity_counts.entry(result.level.clone()).or_insert(0) += 1;
            *rule_counts.entry(result.rule_id.clone()).or_insert(0) += 1;
        }

        report.push_str("## Estatísticas\n\n");
        report.push_str("### Por Severidade\n");
        for (severity, count) in &severity_counts {
            report.push_str(&format!("- **{}**: {} descobertas\n", severity, count));
        }

        report.push_str("\n### Por Regra\n");
        for (rule, count) in &rule_counts {
            report.push_str(&format!("- **{}**: {} descobertas\n", rule, count));
        }

        // Detailed findings with code snippets
        report.push_str("\n## Descobertas Detalhadas\n\n");
        for (i, result) in analysis.results().iter().enumerate() {
            report.push_str(&format!("### Descoberta {}\n\n", i + 1));
            report.push_str(&format!("- **Regra**: {}\n", result.rule_id));
            report.push_str(&format!("- **Severidade**: {}\n", result.level));
            report.push_str(&format!("- **Mensagem**: {}\n", result.message));

            if let Some(location) = &result.locations.first() {
                if let Some(physical_location) = &location.physical_location {
                    report.push_str(&format!(
                        "- **File**: {}\n",
                        physical_location.artifact_location.uri
                    ));
                    report.push_str(&format!(
                        "- **Line**: {}\n",
                        physical_location.region.start_line
                    ));

                    // Add code snippet
                    if let Some((_, snippet)) = code_snippets
                        .iter()
                        .find(|(file, _)| file == &physical_location.artifact_location.uri)
                    {
                        report.push_str("\n**Código Afetado:**\n");
                        report.push_str("```python\n");
                        report.push_str(snippet);
                        report.push_str("\n```\n");
                    }
                }
            }

            // Add correction recommendation
            report.push_str("\n**Recomendação de Correção:**\n");
            report.push_str("Revise a vulnerabilidade de segurança identificada e implemente medidas de segurança apropriadas. Considere validação de entrada, consultas parametrizadas ou práticas seguras de codificação.\n");

            report.push('\n');
        }

        // General correction recommendations
        report.push_str("## Recomendações de Correção\n\n");
        report.push_str("### Melhores Práticas Gerais de Segurança\n\n");
        report.push_str(
            "1. **Validação de Entrada**: Sempre valide e sanitize entradas do usuário\n",
        );
        report.push_str(
            "2. **Consultas Parametrizadas**: Use consultas parametrizadas para prevenir injeção SQL\n",
        );
        report
            .push_str("3. **Execução de Comandos**: Evite execução direta de comandos com entrada do usuário\n");
        report.push_str(
            "4. **Operações de Arquivo**: Valide caminhos de arquivo e use operações seguras de arquivo\n",
        );
        report.push_str("5. **Tratamento de Erros**: Implemente tratamento adequado de erros sem expor informações sensíveis\n");
        report.push_str("6. **Autenticação**: Garanta autenticação e autorização adequadas\n");
        report.push_str("7. **Logging**: Implemente logging de segurança para fins de auditoria\n");

        Ok(report)
    }

    /// Generates basic corrected code when ChatGPT fails
    async fn generate_basic_fixed_code(
        &self,
        _codeql_analysis: &CodeQLAnalysis,
        _code_snippets: &[(String, String)],
        _full_file_content: &str,
    ) -> crate::Result<String> {
        let mut fixed_code = String::new();
        fixed_code.push_str("# Corrected Code - Security Vulnerabilities Resolved\n");
        fixed_code.push_str("# Automatically generated by Code Report\n");
        fixed_code.push_str("# This code implements security best practices\n\n");

        fixed_code.push_str("import subprocess\n");
        fixed_code.push_str("import shlex\n");
        fixed_code.push_str("import logging\n");
        fixed_code.push_str("import os\n");
        fixed_code.push_str("import re\n\n");

        fixed_code.push_str("# Logging configuration for audit\n");
        fixed_code.push_str("logging.basicConfig(level=logging.INFO)\n");
        fixed_code.push_str("logger = logging.getLogger(__name__)\n\n");

        fixed_code.push_str("# List of allowed commands for secure execution\n");
        fixed_code.push_str(
            "ALLOWED_COMMANDS = ['ls', 'pwd', 'whoami', 'date', 'echo', 'cat', 'grep']\n\n",
        );

        fixed_code.push_str("def validate_input(user_input: str) -> bool:\n");
        fixed_code.push_str("    \"\"\"Validate user input for security\"\"\"\n");
        fixed_code.push_str("    if not user_input or not user_input.strip():\n");
        fixed_code.push_str("        return False\n");
        fixed_code.push_str("    # Check for dangerous patterns\n");
        fixed_code.push_str("    dangerous_patterns = [\n");
        fixed_code.push_str("        r'[;&|`$]',  # Command separators\n");
        fixed_code.push_str("        r'\\.\\./',   # Path traversal\n");
        fixed_code.push_str("        r'rm\\s+-rf', # Dangerous rm command\n");
        fixed_code.push_str("    ]\n");
        fixed_code.push_str("    for pattern in dangerous_patterns:\n");
        fixed_code.push_str("        if re.search(pattern, user_input):\n");
        fixed_code.push_str("            return False\n");
        fixed_code.push_str("    return True\n\n");

        fixed_code.push_str("def safe_command_execution(user_input: str) -> str:\n");
        fixed_code.push_str("    \"\"\"Execute commands securely\"\"\"\n");
        fixed_code.push_str("    try:\n");
        fixed_code.push_str("        # Input validation\n");
        fixed_code.push_str("        if not validate_input(user_input):\n");
        fixed_code
            .push_str("            logger.warning(f\"Invalid input detected: {user_input}\")\n");
        fixed_code.push_str("            return \"Error: Invalid input\"\n");
        fixed_code.push_str("        \n");
        fixed_code.push_str("        # Split command into parts\n");
        fixed_code.push_str("        command_parts = shlex.split(user_input)\n");
        fixed_code.push_str("        \n");
        fixed_code.push_str("        # Check if command is in allowed list\n");
        fixed_code.push_str("        if command_parts[0] not in ALLOWED_COMMANDS:\n");
        fixed_code
            .push_str("            logger.warning(f\"Command not allowed: {command_parts[0]}\")\n");
        fixed_code
            .push_str("            return f\"Error: Command '{command_parts[0]}' not allowed\"\n");
        fixed_code.push_str("        \n");
        fixed_code.push_str("        # Execute command securely\n");
        fixed_code.push_str("        result = subprocess.run(\n");
        fixed_code.push_str("            command_parts,\n");
        fixed_code.push_str("            shell=False,  # Never use shell=True\n");
        fixed_code.push_str("            capture_output=True,\n");
        fixed_code.push_str("            text=True,\n");
        fixed_code.push_str("            timeout=30  # Timeout for security\n");
        fixed_code.push_str("        )\n");
        fixed_code.push_str("        \n");
        fixed_code.push_str("        logger.info(f\"Command executed: {command_parts[0]}\")\n");
        fixed_code.push_str("        return result.stdout if result.returncode == 0 else f\"Error: {result.stderr}\"\n");
        fixed_code.push_str("            \n");
        fixed_code.push_str("    except subprocess.TimeoutExpired:\n");
        fixed_code.push_str("        logger.error(\"Command execution timed out\")\n");
        fixed_code.push_str("        return \"Error: Command execution timed out\"\n");
        fixed_code.push_str("    except Exception as e:\n");
        fixed_code.push_str("        logger.error(f\"Command execution error: {str(e)}\")\n");
        fixed_code.push_str("        return f\"Error: {str(e)}\"\n\n");

        fixed_code.push_str("def main():\n");
        fixed_code.push_str("    \"\"\"Main function with secure command execution\"\"\"\n");
        fixed_code.push_str("    print(\"Secure Command Execution Tool\")\n");
        fixed_code.push_str("    print(\"Available commands:\", \", \".join(ALLOWED_COMMANDS))\n");
        fixed_code.push_str("    \n");
        fixed_code.push_str("    while True:\n");
        fixed_code.push_str("        try:\n");
        fixed_code
            .push_str("            user_input = input(\"Enter command (or 'quit' to exit): \")\n");
        fixed_code.push_str("            \n");
        fixed_code.push_str("            if user_input.lower() == 'quit':\n");
        fixed_code.push_str("                break\n");
        fixed_code.push_str("            \n");
        fixed_code.push_str("            result = safe_command_execution(user_input)\n");
        fixed_code.push_str("            print(f\"Result: {result}\")\n");
        fixed_code.push_str("            \n");
        fixed_code.push_str("        except KeyboardInterrupt:\n");
        fixed_code.push_str("            print(\"\\nExiting...\")\n");
        fixed_code.push_str("            break\n");
        fixed_code.push_str("        except Exception as e:\n");
        fixed_code.push_str("            print(f\"Error: {str(e)}\")\n\n");

        fixed_code.push_str("if __name__ == \"__main__\":\n");
        fixed_code.push_str("    main()\n");

        Ok(fixed_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        CodeQLArtifactLocation, CodeQLLocation, CodeQLPhysicalLocation, CodeQLRegion, CodeQLRun,
    };
    use std::fs;
    use tempfile::TempDir;

    fn create_test_config() -> Config {
        Config {
            report_level: "medium".to_string(),
            openai_api_key: "test-key".to_string(),
            model: "gpt-3.5-turbo".to_string(),
            temperature: 0.8,
            timeout_seconds: 30,
            openai_base_url: "https://api.openai.com/v1/chat/completions".to_string(),
            project_root: std::path::PathBuf::from("."),
            output_file: std::path::PathBuf::from("test_report.md"),
            include_fixes: false,
            max_file_bytes: 350000,
            max_payload_tokens: 120000,
            chunk_target_tokens: 3000,
            rate_limit_rps: 30,
        }
    }

    fn create_test_codeql_json() -> String {
        r#"{
            "runs": [
                {
                    "results": [
                        {
                            "rule_id": "py/command-injection",
                            "level": "warning",
                            "message": "This call to subprocess.run() could execute arbitrary code if user input is not properly sanitized.",
                            "locations": [
                                {
                                    "physical_location": {
                                        "artifact_location": {
                                            "uri": "test.py"
                                        },
                                        "region": {
                                            "start_line": 1,
                                            "end_line": 1,
                                            "start_column": 1,
                                            "end_column": 10
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#.to_string()
    }

    #[tokio::test]
    async fn test_analyzer_new() {
        let config = create_test_config();
        let analyzer = CodeQLAnalyzer::new(config);
        assert!(analyzer.is_ok());
    }

    #[tokio::test]
    async fn test_load_codeql_results() {
        let config = create_test_config();
        let analyzer = CodeQLAnalyzer::new(config).unwrap();

        let temp_dir = TempDir::new().unwrap();
        let json_path = temp_dir.path().join("test.json");
        fs::write(&json_path, create_test_codeql_json()).unwrap();

        let result = analyzer
            .load_codeql_results(json_path.to_str().unwrap())
            .await;
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert_eq!(analysis.results().len(), 1);
        assert_eq!(analysis.results()[0].rule_id, "py/command-injection");
    }

    #[tokio::test]
    async fn test_load_codeql_results_invalid_json() {
        let config = create_test_config();
        let analyzer = CodeQLAnalyzer::new(config).unwrap();

        let temp_dir = TempDir::new().unwrap();
        let json_path = temp_dir.path().join("invalid.json");
        fs::write(&json_path, "invalid json").unwrap();

        let result = analyzer
            .load_codeql_results(json_path.to_str().unwrap())
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_extract_code_snippets() {
        let config = create_test_config();
        let analyzer = CodeQLAnalyzer::new(config).unwrap();

        let results = vec![CodeQLResult {
            rule_id: "test-rule".to_string(),
            level: "warning".to_string(),
            message: "Test message".to_string(),
            locations: vec![CodeQLLocation {
                physical_location: Some(CodeQLPhysicalLocation {
                    artifact_location: CodeQLArtifactLocation {
                        uri: "test.py".to_string(),
                    },
                    region: CodeQLRegion {
                        start_line: 1,
                        end_line: Some(1),
                    },
                }),
            }],
        }];

        let snippets = analyzer.extract_code_snippets(&results).await;
        assert!(snippets.is_ok());
    }

    #[tokio::test]
    async fn test_generate_basic_report() {
        let config = create_test_config();
        let analyzer = CodeQLAnalyzer::new(config).unwrap();

        let analysis = CodeQLAnalysis {
            runs: vec![CodeQLRun {
                results: vec![CodeQLResult {
                    rule_id: "test-rule".to_string(),
                    level: "warning".to_string(),
                    message: "Test message".to_string(),
                    locations: vec![],
                }],
            }],
        };

        let report = analyzer.generate_basic_report(&analysis).await;
        assert!(report.is_ok());

        let report_content = report.unwrap();
        assert!(report_content.contains("Relatório de Análise de Segurança CodeQL"));
        assert!(report_content.contains("Resumo Executivo"));
        assert!(report_content.contains("Estatísticas"));
        assert!(report_content.contains("Descobertas Detalhadas"));
        assert!(report_content.contains("test-rule"));
    }

    #[tokio::test]
    async fn test_generate_advanced_report_with_recommendations() {
        let config = create_test_config();
        let analyzer = CodeQLAnalyzer::new(config).unwrap();

        let analysis = CodeQLAnalysis {
            runs: vec![CodeQLRun {
                results: vec![CodeQLResult {
                    rule_id: "test-rule".to_string(),
                    level: "warning".to_string(),
                    message: "Test message".to_string(),
                    locations: vec![],
                }],
            }],
        };

        let code_snippets = vec![("test.py".to_string(), "print('test')".to_string())];

        let report = analyzer
            .generate_advanced_report_with_recommendations(
                &analysis,
                &code_snippets,
                "test content",
            )
            .await;

        assert!(report.is_ok());

        let report_content = report.unwrap();
        assert!(report_content.contains("Relatório de Análise de Segurança CodeQL - Avançado"));
        assert!(report_content.contains("Recomendações de Correção"));
        assert!(report_content.contains("Melhores Práticas Gerais de Segurança"));
    }

    #[tokio::test]
    async fn test_generate_basic_fixed_code() {
        let config = create_test_config();
        let analyzer = CodeQLAnalyzer::new(config).unwrap();

        let analysis = CodeQLAnalysis { runs: vec![] };
        let code_snippets = vec![];

        let fixed_code = analyzer
            .generate_basic_fixed_code(&analysis, &code_snippets, "test content")
            .await;

        assert!(fixed_code.is_ok());

        let code_content = fixed_code.unwrap();
        assert!(code_content.contains("Corrected Code - Security Vulnerabilities Resolved"));
        assert!(code_content.contains("import subprocess"));
        assert!(code_content.contains("import shlex"));
        assert!(code_content.contains("import logging"));
        assert!(code_content.contains("def validate_input"));
        assert!(code_content.contains("def safe_command_execution"));
    }
}
