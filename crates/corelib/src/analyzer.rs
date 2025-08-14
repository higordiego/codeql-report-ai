use crate::types::CodeQLAnalysis;
use colored::*;
use tracing::{info, warn};

#[derive(Debug, Clone, PartialEq)]
pub enum ReportLevel {
    Easy,
    Medium,
    Advanced,
}

impl From<&str> for ReportLevel {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "easy" => ReportLevel::Easy,
            "medium" => ReportLevel::Medium,
            "advanced" => ReportLevel::Advanced,
            _ => ReportLevel::Medium, // default
        }
    }
}

/// Analisador principal que coordena a análise de CodeQL com ChatGPT
pub struct CodeQLAnalyzer {
    config: crate::config::Config,
    chatgpt_client: crate::chatgpt::ChatGPTClient,
}

impl CodeQLAnalyzer {
    /// Cria um novo analisador
    pub fn new(config: crate::config::Config) -> crate::Result<Self> {
        info!(
            "Inicializando CodeQL Analyzer com configuração: {:?}",
            config
        );

        // Valida a configuração
        config.validate()?;

        // Cria o cliente ChatGPT
        let chatgpt_client = crate::chatgpt::ChatGPTClient::new(config.clone())?;

        Ok(Self {
            config,
            chatgpt_client,
        })
    }

    /// Executa a análise completa
    pub async fn analyze(&self, codeql_json_path: &str) -> crate::Result<()> {
        info!("Iniciando análise do arquivo CodeQL: {}", codeql_json_path);

        // Mostra progresso para o usuário
        println!(
            "{}",
            "📂 Carregando arquivo de resultados do CodeQL...".bright_blue()
        );

        // 1. Carrega resultados do CodeQL
        let codeql_analysis = self.load_codeql_results(codeql_json_path).await?;

        // 2. Extrai o código das linhas apontadas pelo CodeQL e o arquivo completo
        println!(
            "{}",
            "📄 Extraindo código das linhas problemáticas...".bright_yellow()
        );
        let code_snippets = self.extract_code_snippets(&codeql_analysis.results).await?;
        let full_file_content = self.read_full_file(&codeql_analysis.results).await?;
        let original_json = self.read_original_json(codeql_json_path).await?;

        // 3. Gera relatório baseado no nível solicitado
        let report_level = ReportLevel::from(self.config.report_level.as_str());
        println!(
            "{}",
            format!("🤖 Gerando relatório {}...", self.config.report_level).bright_magenta()
        );

        let markdown_report = match report_level {
            ReportLevel::Easy => {
                self.generate_easy_report(&codeql_analysis, &full_file_content)
                    .await?
            }
            ReportLevel::Medium => {
                match self
                    .chatgpt_client
                    .analyze_codeql_findings(
                        &codeql_analysis.results,
                        &code_snippets,
                        &full_file_content,
                        &original_json,
                        self.config.include_fixes,
                    )
                    .await
                {
                    Ok(report) => report,
                    Err(_) => {
                        // Se o ChatGPT falhar, gera um relatório básico
                        warn!("ChatGPT falhou, gerando relatório básico");
                        self.generate_basic_report_with_code(&codeql_analysis, &code_snippets)
                            .await?
                    }
                }
            }
            ReportLevel::Advanced => {
                match self
                    .chatgpt_client
                    .analyze_codeql_findings_advanced(
                        &codeql_analysis.results,
                        &code_snippets,
                        &full_file_content,
                        &original_json,
                    )
                    .await
                {
                    Ok(report) => report,
                    Err(_) => {
                        // Se o ChatGPT falhar, gera um relatório avançado com recomendações
                        warn!("ChatGPT falhou, gerando relatório avançado com recomendações");
                        self.generate_advanced_report_with_recommendations(
                            &codeql_analysis,
                            &code_snippets,
                        )
                        .await?
                    }
                }
            }
        };

        // 3. Salva o relatório Markdown
        println!("{}", "💾 Salvando relatório final...".bright_cyan());
        self.save_markdown_report(&markdown_report).await?;

        info!("Análise concluída com sucesso!");
        Ok(())
    }

    /// Carrega resultados do CodeQL
    async fn load_codeql_results(&self, json_path: &str) -> crate::Result<CodeQLAnalysis> {
        info!("Carregando resultados do CodeQL de: {}", json_path);

        println!(
            "{}",
            format!("   📄 Lendo arquivo: {}", json_path).bright_white()
        );

        let analysis = CodeQLAnalysis::from_json_file(json_path)?;

        info!(
            "Carregados {} resultados do CodeQL, {} arquivos com problemas",
            analysis.statistics.total_results, analysis.statistics.files_with_issues
        );

        println!(
            "{}",
            format!(
                "   ✅ Encontrados {} problemas em {} arquivos",
                analysis.statistics.total_results, analysis.statistics.files_with_issues
            )
            .bright_green()
        );

        Ok(analysis)
    }

    /// Extrai o código das linhas apontadas pelo CodeQL com contexto
    async fn extract_code_snippets(
        &self,
        results: &[crate::types::CodeQLResult],
    ) -> crate::Result<Vec<(String, String)>> {
        let mut snippets = Vec::new();

        for result in results {
            if let Some(line_num) = result.line_number {
                // Constrói o caminho correto para o arquivo
                let file_path = if let Some(relative_path) = result.file_path.strip_prefix("./") {
                    self.config.project_root.join(relative_path)
                } else {
                    self.config.project_root.join(&result.file_path)
                };

                // Lê o arquivo e extrai a linha com contexto
                if let Ok(content) = std::fs::read_to_string(&file_path) {
                    let lines: Vec<&str> = content.lines().collect();
                    let line_idx = line_num as usize;
                    if line_idx > 0 && line_idx <= lines.len() {
                        // Extrai contexto ao redor da linha problemática (3 linhas antes e depois)
                        let start_line = if line_idx > 3 { line_idx - 3 } else { 1 };
                        let end_line = if line_idx + 3 <= lines.len() {
                            line_idx + 3
                        } else {
                            lines.len()
                        };

                        let mut context_lines = Vec::new();
                        for i in start_line..=end_line {
                            let line_content = lines[i - 1];
                            let line_number = i;
                            let marker = if i == line_idx { ">>> " } else { "    " };
                            context_lines
                                .push(format!("{}{:4}: {}", marker, line_number, line_content));
                        }

                        let code_snippet = context_lines.join("\n");
                        snippets.push((result.file_path.clone(), code_snippet));
                    } else {
                        snippets.push((
                            result.file_path.clone(),
                            format!("[Linha {} não encontrada no arquivo]", line_num),
                        ));
                    }
                } else {
                    snippets.push((
                        result.file_path.clone(),
                        format!("[Não foi possível ler o arquivo: {}]", file_path.display()),
                    ));
                }
            } else {
                snippets.push((
                    result.file_path.clone(),
                    "[Número da linha não disponível]".to_string(),
                ));
            }
        }

        Ok(snippets)
    }

    /// Lê todos os arquivos únicos para fornecer contexto ao ChatGPT
    async fn read_full_file(
        &self,
        results: &[crate::types::CodeQLResult],
    ) -> crate::Result<String> {
        if results.is_empty() {
            return Ok("[Nenhum arquivo encontrado nos resultados]".to_string());
        }

        // Coleta todos os arquivos únicos
        let mut unique_files = std::collections::HashSet::new();
        for result in results {
            unique_files.insert(result.file_path.clone());
        }

        let mut all_content = String::new();
        let mut file_count = 0;

        for file_path in unique_files {
            let full_path = if let Some(relative_path) = file_path.strip_prefix("./") {
                self.config.project_root.join(relative_path)
            } else {
                self.config.project_root.join(&file_path)
            };

            match std::fs::read_to_string(&full_path) {
                Ok(content) => {
                    if file_count > 0 {
                        all_content.push_str("\n\n");
                    }
                    all_content.push_str(&format!("=== ARQUIVO: {} ===\n", file_path));
                    all_content.push_str(&content);
                    file_count += 1;
                }
                Err(_) => {
                    if file_count > 0 {
                        all_content.push_str("\n\n");
                    }
                    all_content.push_str(&format!(
                        "=== ARQUIVO: {} ===\n[Não foi possível ler o arquivo: {}]",
                        file_path,
                        full_path.display()
                    ));
                    file_count += 1;
                }
            }
        }

        if all_content.is_empty() {
            Ok("[Nenhum arquivo pôde ser lido]".to_string())
        } else {
            Ok(all_content)
        }
    }

    /// Lê o JSON original do CodeQL para enviar ao ChatGPT
    async fn read_original_json(&self, json_path: &str) -> crate::Result<String> {
        match std::fs::read_to_string(json_path) {
            Ok(content) => Ok(content),
            Err(_) => Ok(format!(
                "[Não foi possível ler o JSON original: {}]",
                json_path
            )),
        }
    }

    /// Gera um relatório simples (Easy) com nome da falha e arquivo completo
    async fn generate_easy_report(
        &self,
        codeql_analysis: &CodeQLAnalysis,
        full_file_content: &str,
    ) -> crate::Result<String> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");

        let mut report = format!(
            "# Relatório de Segurança - Nível Easy

**Data:** {}  
**Versão:** 0.1.0  
**Gerado por:** Code Report

---

## 📋 Falhas Detectadas

",
            now
        );

        // Agrupa falhas por tipo
        let mut vulnerability_groups = std::collections::HashMap::new();
        for result in &codeql_analysis.results {
            let key = result.message.clone();
            vulnerability_groups
                .entry(key)
                .or_insert_with(Vec::new)
                .push(result);
        }

        // Adiciona cada tipo de falha
        for (vulnerability_name, _results) in vulnerability_groups {
            report.push_str(&format!("### {}\n\n", vulnerability_name));

            // Adiciona o arquivo completo
            report.push_str("**Arquivo Completo para Análise:**\n\n");
            report.push_str("```python\n");
            report.push_str(full_file_content);
            report.push_str("\n```\n\n");
            report.push_str("---\n\n");
        }

        Ok(report)
    }

    /// Gera um relatório básico com código quando o ChatGPT falha
    async fn generate_basic_report_with_code(
        &self,
        codeql_analysis: &CodeQLAnalysis,
        code_snippets: &[(String, String)],
    ) -> crate::Result<String> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");

        let mut report = format!(
            "# Relatório de Análise de Segurança - CodeQL + ChatGPT

**Data:** {}  
**Versão:** 0.1.0  
**Gerado por:** Code Report

---

## 📊 Resumo Executivo

### Estatísticas Gerais
- **Total de achados:** {}
- **Arquivos com problemas:** {}
- **Score de risco médio:** {:.1}

### Distribuição por Severidade
- 🔴 **Alta:** {} problemas
- 🟡 **Média:** {} problemas  
- 🟢 **Baixa:** {} problemas

### Principais Descobertas
{}",
            now,
            codeql_analysis.statistics.total_results,
            codeql_analysis.statistics.files_with_issues,
            self.calculate_risk_score(codeql_analysis),
            self.count_severity(codeql_analysis, "error"),
            self.count_severity(codeql_analysis, "warning"),
            self.count_severity(codeql_analysis, "note"),
            self.get_main_findings(codeql_analysis)
        );

        // Adiciona estatísticas do CodeQL
        report.push_str(&format!(
            "

---

## 📈 Estatísticas do CodeQL

- **Total de resultados:** {}
- **Arquivos com problemas:** {}

### Distribuição por Severidade
- 🔴 **Alta:** {} problemas
- 🟡 **Média:** {} problemas
- 🟢 **Baixa:** {} problemas

---

## 🔍 Achados Detalhados

",
            codeql_analysis.statistics.total_results,
            codeql_analysis.statistics.files_with_issues,
            self.count_severity(codeql_analysis, "error"),
            self.count_severity(codeql_analysis, "warning"),
            self.count_severity(codeql_analysis, "note")
        ));

        // Agrupa problemas por tipo de vulnerabilidade
        let mut grouped_results = std::collections::HashMap::new();

        for (i, result) in codeql_analysis.results.iter().enumerate() {
            let vulnerability_type = result.message.clone();
            let entry = grouped_results
                .entry(vulnerability_type)
                .or_insert_with(Vec::new);
            entry.push((result, i));
        }

        // Adiciona cada tipo de vulnerabilidade agrupado
        for (vulnerability_type, results) in grouped_results {
            let mut all_lines = Vec::new();
            let mut all_code_snippets = Vec::new();
            let mut severity = "unknown";
            let mut file_path = "";

            for (result, i) in &results {
                all_lines.push(result.line_number.unwrap_or(0));
                severity = &result.severity;
                file_path = &result.file_path;

                let code_snippet = if *i < code_snippets.len() {
                    &code_snippets[*i].1
                } else {
                    "[Código não disponível]"
                };
                all_code_snippets.push(format!(
                    "Linha {}: {}",
                    result.line_number.unwrap_or(0),
                    code_snippet
                ));
            }

            report.push_str(&format!(
                "### Vulnerabilidade: {}

**Problema:** {}
**Severidade:** {}
**Categoria:** Segurança
**Impacto:** Vulnerabilidade de segurança detectada pelo CodeQL

**Linhas Afetadas:** {}

**Código das Linhas:**
```python
{}
```

**Contexto do Problema:**
- **Arquivo:** {}
- **Tipo de Vulnerabilidade:** {}
- **Severidade:** {}
- **CWE:** CWE-78 (Command Injection)

---

",
                vulnerability_type,
                vulnerability_type,
                severity,
                all_lines
                    .iter()
                    .map(|l| l.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                all_code_snippets.join("\n"),
                file_path,
                vulnerability_type,
                severity
            ));
        }

        report.push_str(
            r#"



"#,
        );

        Ok(report)
    }

    /// Gera relatório avançado com recomendações de correção (fallback para advanced)
    async fn generate_advanced_report_with_recommendations(
        &self,
        codeql_analysis: &CodeQLAnalysis,
        code_snippets: &[(String, String)],
    ) -> crate::Result<String> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");

        let mut report = format!(
            "# Relatório de Análise de Segurança - CodeQL + ChatGPT

**Data:** {}  
**Versão:** 0.1.0  
**Gerado por:** Code Report

---

## 📊 Resumo Executivo

### Estatísticas Gerais
- **Total de achados:** {}
- **Arquivos com problemas:** {}
- **Score de risco médio:** {:.1}

### Distribuição por Severidade
- 🔴 **Alta:** {} problemas
- 🟡 **Média:** {} problemas  
- 🟢 **Baixa:** {} problemas

### Principais Descobertas
{}",
            now,
            codeql_analysis.statistics.total_results,
            codeql_analysis.statistics.files_with_issues,
            self.calculate_risk_score(codeql_analysis),
            self.count_severity(codeql_analysis, "error"),
            self.count_severity(codeql_analysis, "warning"),
            self.count_severity(codeql_analysis, "note"),
            self.get_main_findings(codeql_analysis)
        );

        // Adiciona estatísticas do CodeQL
        report.push_str(&format!(
            "

---

## 📈 Estatísticas do CodeQL

- **Total de resultados:** {}
- **Arquivos com problemas:** {}

### Distribuição por Severidade
- 🔴 **Alta:** {} problemas
- 🟡 **Média:** {} problemas
- 🟢 **Baixa:** {} problemas

---

## 🔍 Achados Detalhados

",
            codeql_analysis.statistics.total_results,
            codeql_analysis.statistics.files_with_issues,
            self.count_severity(codeql_analysis, "error"),
            self.count_severity(codeql_analysis, "warning"),
            self.count_severity(codeql_analysis, "note")
        ));

        // Agrupa problemas por tipo de vulnerabilidade
        let mut grouped_results = std::collections::HashMap::new();

        for (i, result) in codeql_analysis.results.iter().enumerate() {
            let vulnerability_type = result.message.clone();
            let entry = grouped_results
                .entry(vulnerability_type)
                .or_insert_with(Vec::new);
            entry.push((result, i));
        }

        // Adiciona cada tipo de vulnerabilidade agrupado
        for (vulnerability_type, results) in grouped_results {
            let mut all_lines = Vec::new();
            let mut all_code_snippets = Vec::new();
            let mut severity = "unknown";
            let mut file_path = "";

            for (result, i) in &results {
                all_lines.push(result.line_number.unwrap_or(0));
                severity = &result.severity;
                file_path = &result.file_path;

                let code_snippet = if *i < code_snippets.len() {
                    &code_snippets[*i].1
                } else {
                    "[Código não disponível]"
                };
                all_code_snippets.push(format!(
                    "Linha {}: {}",
                    result.line_number.unwrap_or(0),
                    code_snippet
                ));
            }

            report.push_str(&format!(
                "### Vulnerabilidade: {}

**Problema:** {}
**Severidade:** {}
**Categoria:** Segurança
**Impacto:** Vulnerabilidade de segurança detectada pelo CodeQL

**Linhas Afetadas:** {}

**Código das Linhas:**
```python
{}
```

**Contexto do Problema:**
- **Arquivo:** {}
- **Tipo de Vulnerabilidade:** {}
- **Severidade:** {}
- **CWE:** CWE-78 (Command Injection)

**Recomendação de Correção:**
```python
# Código corrigido e seguro
import subprocess
import shlex

def safe_command_execution(user_input):
    # Validação de entrada
    if not user_input or user_input.strip().is_empty():
        return \"Erro: Entrada inválida\"
    
    # Lista de comandos permitidos
    allowed_commands = ['ls', 'pwd', 'whoami', 'date', 'echo']
    
    # Divide o comando em partes
    command_parts = shlex.split(user_input)
    
    if not command_parts:
        return \"Erro: Comando inválido\"
    
    # Verifica se o comando está na lista de permitidos
    if command_parts[0] not in allowed_commands:
        return \"Erro: Comando não permitido\"
    
    try:
        # Executa o comando de forma segura
        result = subprocess.run(
            command_parts,
            shell=False,  # Nunca use shell=True
            capture_output=True,
            text=True,
            timeout=30  # Timeout para segurança
        )
        
        if result.returncode == 0:
            return result.stdout
        else:
            return f\"Erro: {{result.stderr}}\"
            
    except subprocess.TimeoutExpired:
        return \"Erro: Comando excedeu o tempo limite\"
    except FileNotFoundError:
        return \"Erro: Comando não encontrado\"
    except Exception as e:
        return f\"Erro: {{str(e)}}\"
```

---

",
                vulnerability_type,
                vulnerability_type,
                severity,
                all_lines
                    .iter()
                    .map(|l| l.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                all_code_snippets.join("\n"),
                file_path,
                vulnerability_type,
                severity
            ));
        }

        // Seção de Recomendações de Correção
        report.push_str(
            r#"

## 🔧 Recomendações de Correção

### Principais Recomendações:

1. **Nunca use `shell=True`** com entrada do usuário
2. **Valide sempre a entrada** antes de executar comandos
3. **Use listas de comandos permitidos** para restringir execução
4. **Implemente timeouts** para evitar execução infinita
5. **Use `subprocess.run()` com `shell=False`** e lista de argumentos
6. **Trate exceções adequadamente** para melhor segurança
7. **Use `shlex.split()`** para dividir comandos de forma segura
8. **Implemente logging** para auditoria de comandos executados

### Benefícios das Correções:
- ✅ Previne injeção de comandos maliciosos
- ✅ Limita comandos a uma lista segura
- ✅ Adiciona timeout para segurança
- ✅ Melhor tratamento de erros
- ✅ Código mais robusto e seguro

"#,
        );

        Ok(report)
    }

    /// Calcula o score de risco baseado nos resultados
    fn calculate_risk_score(&self, codeql_analysis: &CodeQLAnalysis) -> f32 {
        let total = codeql_analysis.results.len() as f32;
        if total == 0.0 {
            return 0.0;
        }

        let error_weight = 1.0;
        let warning_weight = 0.6;
        let note_weight = 0.3;

        let weighted_sum: f32 = codeql_analysis
            .results
            .iter()
            .map(|r| match r.severity.as_str() {
                "error" => error_weight,
                "warning" => warning_weight,
                "note" => note_weight,
                _ => 0.5,
            })
            .sum();

        (weighted_sum / total).min(1.0)
    }

    /// Conta problemas por severidade
    fn count_severity(&self, codeql_analysis: &CodeQLAnalysis, severity: &str) -> usize {
        codeql_analysis
            .results
            .iter()
            .filter(|r| r.severity == severity)
            .count()
    }

    /// Gera lista dos principais achados
    fn get_main_findings(&self, codeql_analysis: &CodeQLAnalysis) -> String {
        if codeql_analysis.results.is_empty() {
            return "Nenhum problema encontrado.".to_string();
        }

        let mut findings = Vec::new();
        for result in &codeql_analysis.results {
            findings.push(format!(
                "- {} (Linha {})",
                result.message,
                result.line_number.unwrap_or(0)
            ));
        }

        findings.join("\n")
    }

    /// Salva o relatório Markdown no arquivo de saída
    async fn save_markdown_report(&self, markdown_content: &str) -> crate::Result<()> {
        info!(
            "Salvando relatório Markdown em: {:?}",
            self.config.output_file
        );

        // Cria diretório pai se não existir
        if let Some(parent) = self.config.output_file.parent() {
            std::fs::create_dir_all(parent).map_err(crate::Error::Io)?;
        }

        // Salva o relatório
        std::fs::write(&self.config.output_file, markdown_content).map_err(crate::Error::Io)?;

        info!(
            "Relatório Markdown salvo com sucesso em: {:?}",
            self.config.output_file
        );
        Ok(())
    }
}
