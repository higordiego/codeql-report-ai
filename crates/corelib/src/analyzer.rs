use crate::types::*;
use tracing::{debug, error, info, warn};
use colored::*;

/// Analisador principal que coordena a análise de CodeQL com ChatGPT
pub struct CodeQLAnalyzer {
    config: crate::config::Config,
    chatgpt_client: crate::chatgpt::ChatGPTClient,
}

impl CodeQLAnalyzer {
    /// Cria um novo analisador
    pub fn new(config: crate::config::Config) -> crate::Result<Self> {
        info!("Inicializando CodeQL Analyzer com configuração: {:?}", config);
        
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
        println!("{}", "📂 Carregando arquivo de resultados do CodeQL...".bright_blue());
        
        // 1. Carrega resultados do CodeQL
        let codeql_analysis = self.load_codeql_results(codeql_json_path).await?;
        
        // 2. Encontra arquivos Python relevantes
        println!("{}", "🔍 Procurando arquivos Python no projeto...".bright_green());
        let python_files = self.find_relevant_files(&codeql_analysis).await?;
        
        // 3. Cria chunks de arquivos (apenas linhas específicas reportadas)
        println!("{}", "✂️  Preparando código para análise...".bright_yellow());
        let chunks = self.create_analysis_chunks(python_files, &codeql_analysis.results).await?;
        
        // 4. Analisa cada chunk com ChatGPT (passando os resultados do CodeQL)
        println!("{}", "🤖 Analisando código com IA...".bright_magenta());
        let markdown_report = match self.analyze_chunks_with_chatgpt(chunks, &codeql_analysis.results).await {
            Ok(report) => report,
            Err(_) => {
                // Se o ChatGPT falhar, gera um relatório básico com os problemas do CodeQL
                warn!("ChatGPT falhou, gerando relatório básico com problemas do CodeQL");
                self.generate_basic_report(&codeql_analysis).await?
            }
        };
        
        // 5. Salva o relatório Markdown diretamente
        println!("{}", "💾 Salvando relatório final...".bright_cyan());
        self.save_markdown_report(&markdown_report).await?;
        
        info!("Análise concluída com sucesso!");
        Ok(())
    }
    
    /// Carrega resultados do CodeQL
    async fn load_codeql_results(&self, json_path: &str) -> crate::Result<CodeQLAnalysis> {
        info!("Carregando resultados do CodeQL de: {}", json_path);
        
        println!("{}", format!("   📄 Lendo arquivo: {}", json_path).bright_white());
        
        let analysis = CodeQLAnalysis::from_json_file(json_path)?;
        
        info!(
            "Carregados {} resultados do CodeQL, {} arquivos com problemas",
            analysis.statistics.total_results,
            analysis.statistics.files_with_issues
        );
        
        println!("{}", format!("   ✅ Encontrados {} problemas em {} arquivos", 
            analysis.statistics.total_results, 
            analysis.statistics.files_with_issues).bright_green());
        
        Ok(analysis)
    }
    
    /// Encontra arquivos Python relevantes baseado nos resultados do CodeQL
    async fn find_relevant_files(
        &self,
        codeql_analysis: &CodeQLAnalysis,
    ) -> crate::Result<Vec<std::path::PathBuf>> {
        info!("Procurando arquivos Python relevantes no projeto");
        
        println!("{}", format!("   📁 Escaneando diretório: {}", self.config.project_root.display()).bright_white());
        
        // Obtém arquivos únicos que contêm falhas
        let files_with_issues = codeql_analysis.get_files_with_issues();
        
        // Encontra todos os arquivos Python no projeto
        let all_python_files = crate::utils::find_python_files(&self.config.project_root)?;
        
        info!("Encontrados {} arquivos Python no projeto", all_python_files.len());
        
        println!("{}", format!("   🔍 Encontrados {} arquivos Python no projeto", all_python_files.len()).bright_blue());
        
        // Filtra apenas arquivos que contêm falhas ou são relevantes
        let mut relevant_files = Vec::new();
        
        for file_path in all_python_files {
            let file_str = file_path.to_string_lossy();
            
            // Inclui arquivos com falhas
            if files_with_issues.iter().any(|&f| f == file_str.as_ref()) {
                relevant_files.push(file_path);
                continue;
            }
            
            // Inclui arquivos principais mesmo sem falhas
            if let Some(filename) = file_path.file_name() {
                if filename == "main.py" || filename == "__init__.py" {
                    relevant_files.push(file_path);
                }
            }
        }
        
        info!("Selecionados {} arquivos relevantes para análise", relevant_files.len());
        
        println!("{}", format!("   🎯 Selecionados {} arquivos para análise", relevant_files.len()).bright_yellow());
        
        Ok(relevant_files)
    }
    
    /// Cria chunks de arquivos para análise (apenas linhas específicas reportadas)
    async fn create_analysis_chunks(
        &self,
        files: Vec<std::path::PathBuf>,
        codeql_results: &[CodeQLResult],
    ) -> crate::Result<Vec<Chunk>> {
        info!("Criando chunks direcionados para {} arquivos", files.len());
        
        // Usa a nova função que cria chunks apenas com as linhas específicas
        let chunks = crate::utils::create_targeted_chunks(
            files,
            codeql_results,
            2, // 2 linhas de contexto antes e depois
        )?;
        
        info!("Criados {} chunks direcionados para análise", chunks.len());
        
        for (i, chunk) in chunks.iter().enumerate() {
            debug!(
                "Chunk direcionado {}: arquivo {}, linhas {}-{}, {} tokens",
                i + 1,
                chunk.file_path.display(),
                chunk.start_line,
                chunk.end_line,
                chunk.token_count
            );
        }
        
        Ok(chunks)
    }
    
    /// Analisa chunks com ChatGPT e retorna relatório Markdown
    async fn analyze_chunks_with_chatgpt(
        &self,
        chunks: Vec<Chunk>,
        codeql_results: &[CodeQLResult],
    ) -> crate::Result<String> {
        info!("Iniciando análise de {} chunks com ChatGPT", chunks.len());
        
        let mut markdown_reports = Vec::new();
        
        for (i, chunk) in chunks.iter().enumerate() {
            info!("Analisando chunk {}/{}", i + 1, chunks.len());
            
            match self.analyze_single_chunk(chunk, codeql_results).await {
                Ok(report) => {
                    info!("Chunk {} analisado com sucesso", i + 1);
                    markdown_reports.push(report);
                }
                Err(e) => {
                    error!("Erro ao analisar chunk {}: {}", i + 1, e);
                    warn!("Continuando com os próximos chunks...");
                }
            }
        }
        
        info!("Análise do ChatGPT concluída: {} chunks processados", markdown_reports.len());
        
        // Se nenhum chunk foi processado com sucesso, retorna erro
        if markdown_reports.is_empty() {
            return Err(crate::Error::ChatGPT("Todos os chunks falharam na análise".to_string()));
        }
        
        // Combina todos os relatórios em um único documento
        let combined_report = markdown_reports.join("\n\n---\n\n");
        Ok(combined_report)
    }
    
    /// Analisa um chunk individual
    async fn analyze_single_chunk(
        &self,
        chunk: &Chunk,
        codeql_results: &[CodeQLResult],
    ) -> crate::Result<String> {
        let file_info = chunk.generate_file_info();
        let content = chunk.generate_content();
        
        // Adiciona informações sobre as linhas específicas com problemas
        let error_lines_info = self.generate_error_lines_info(chunk, codeql_results);
        let enhanced_content = format!("{}\n\n{}", content, error_lines_info);
        
        // Verifica se o conteúdo não excede o limite de tokens
        let estimated_tokens = enhanced_content.len() / 4;
        if estimated_tokens > self.config.max_payload_tokens {
            warn!(
                "Chunk muito grande ({} tokens estimados), aplicando truncamento",
                estimated_tokens
            );
            
            // Aplica truncamento inteligente
            let truncated_content = self.truncate_content(&enhanced_content, self.config.max_payload_tokens);
            return self.chatgpt_client.analyze_code_chunk(&truncated_content, &file_info).await;
        }
        
        self.chatgpt_client.analyze_code_chunk(&enhanced_content, &file_info).await
    }
    
    /// Gera informações sobre as linhas específicas com problemas
    fn generate_error_lines_info(&self, chunk: &Chunk, codeql_results: &[CodeQLResult]) -> String {
        let mut error_lines = Vec::new();
        
        for result in codeql_results {
            // Verifica se o resultado é para o arquivo atual
            if result.file_path == chunk.file_path.to_string_lossy() {
                if let Some(line_num) = result.line_number {
                    // Verifica se a linha está dentro do chunk atual
                    if line_num as usize >= chunk.start_line && line_num as usize <= chunk.end_line {
                        let mut line_info = format!(
                            "🚨 LINHA {}: {} (Severidade: {})",
                            line_num,
                            result.message,
                            result.severity
                        );
                        
                        // Adiciona informações de coluna se disponível
                        if let Some(col_num) = result.column_number {
                            line_info.push_str(&format!(" - Coluna: {}", col_num));
                        }
                        
                        // Adiciona informações de linha final se disponível
                        if let Some(end_line) = result.end_line_number {
                            if end_line != line_num {
                                line_info.push_str(&format!(" até linha {}", end_line));
                            }
                        }
                        
                        error_lines.push(line_info);
                    }
                }
            }
        }
        
        if error_lines.is_empty() {
            return String::new();
        }
        
        format!(
            "\n=== LINHAS ESPECÍFICAS ANALISADAS (REPORTADAS PELO CODEQL) ===\n{}\n\n📋 CONTEXTO: Este chunk contém apenas as linhas específicas onde problemas foram detectados, mais 2 linhas de contexto.\n\n⚠️  ANALISE ESTAS LINHAS ESPECÍFICAS E FORNEÇA:\n- Explicação detalhada do problema\n- Impacto de segurança\n- Como corrigir o problema\n- Exemplo de código corrigido\n",
            error_lines.join("\n")
        )
    }
    
    /// Trunca conteúdo para caber no limite de tokens
    fn truncate_content(&self, content: &str, max_tokens: usize) -> String {
        let max_chars = max_tokens * 4; // Estimativa aproximada
        
        if content.len() <= max_chars {
            return content.to_string();
        }
        
        // Mantém o início e o fim, removendo o meio
        let head_size = max_chars / 2;
        let tail_size = max_chars - head_size;
        
        let head = &content[..head_size];
        let tail = &content[content.len() - tail_size..];
        
        format!(
            "{}\n\n... (conteúdo truncado) ...\n\n{}",
            head, tail
        )
    }
    
    /// Gera um relatório básico com os problemas do CodeQL quando o ChatGPT falha
    async fn generate_basic_report(&self, codeql_analysis: &CodeQLAnalysis) -> crate::Result<String> {
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

        // Adiciona cada problema encontrado
        for result in &codeql_analysis.results {
            report.push_str(&format!(
                "### {} - Linha {}

**Problema:** {}
**Severidade:** {}
**Categoria:** Segurança
**Impacto:** Vulnerabilidade de segurança detectada pelo CodeQL
**Recomendação:** Revisar e corrigir o código problemático

**Código Problemático:**
```python
[Linha {}: {}]
```

**Contexto do Problema:**
- **Arquivo:** {}
- **Linha:** {}
- **Função:** {}
- **Severidade:** {}
- **CWE:** CWE-78 (Command Injection)

---

",
                result.file_path,
                result.line_number.unwrap_or(0),
                result.message,
                result.severity,
                result.line_number.unwrap_or(0),
                result.message,
                result.file_path,
                result.line_number.unwrap_or(0),
                "N/A", // Função não disponível no CodeQL
                result.severity
            ));
        }

        // Adiciona recomendações e plano de ação
        report.push_str(&self.generate_recommendations(codeql_analysis));

        // Adiciona metadados
        report.push_str(&format!(
            "

## 📋 Metadados

**Configurações utilizadas:**
- Modelo: gpt-3.5-turbo (falhou - usando relatório básico)
- Temperatura: 0.2
- Rate limit: 30 req/s
- Timeout: 30s

---
*Relatório gerado automaticamente pelo Code Report v0.1.0*

⚠️ **Nota:** Este relatório foi gerado automaticamente com base nos resultados do CodeQL, pois a análise do ChatGPT não pôde ser concluída devido a problemas de conectividade ou autenticação.
"
        ));

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

        let weighted_sum: f32 = codeql_analysis.results.iter().map(|r| {
            match r.severity.as_str() {
                "error" => error_weight,
                "warning" => warning_weight,
                "note" => note_weight,
                _ => 0.5
            }
        }).sum();

        (weighted_sum / total).min(1.0)
    }

    /// Conta problemas por severidade
    fn count_severity(&self, codeql_analysis: &CodeQLAnalysis, severity: &str) -> usize {
        codeql_analysis.results.iter()
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
            findings.push(format!("- {} (Linha {})", result.message, result.line_number.unwrap_or(0)));
        }

        findings.join("\n")
    }

    /// Gera recomendações baseadas nos problemas encontrados
    fn generate_recommendations(&self, codeql_analysis: &CodeQLAnalysis) -> String {
        let error_count = self.count_severity(codeql_analysis, "error");
        let warning_count = self.count_severity(codeql_analysis, "warning");
        let note_count = self.count_severity(codeql_analysis, "note");

        format!(
            "

## 💡 Recomendações

### 🔴 Prioridade Alta (Imediata)
{}",
            if error_count > 0 {
                format!("- Corrigir {} vulnerabilidades críticas de segurança identificadas", error_count)
            } else {
                "Nenhuma ação imediata necessária.".to_string()
            }
        ) + &format!(
            "

### 🟡 Prioridade Média (Próximas 2 semanas)
{}",
            if warning_count > 0 {
                format!("- Revisar {} problemas de qualidade de código", warning_count)
            } else {
                "Nenhuma ação necessária.".to_string()
            }
        ) + &format!(
            "

### 🟢 Prioridade Baixa (Próximo mês)
{}",
            if note_count > 0 {
                format!("- Considerar {} melhorias sugeridas", note_count)
            } else {
                "Continuar monitorando o código para garantir que futuras adições não introduzam vulnerabilidades.".to_string()
            }
        ) + &format!(
            "

## 🎯 Plano de Ação

### 🔴 Prioridade Alta (Imediata)
{}",
            if error_count > 0 {
                format!("- [ ] Corrigir vulnerabilidades críticas de segurança")
            } else {
                "- [ ] Nenhuma ação necessária.".to_string()
            }
        ) + &format!(
            "

### 🟡 Prioridade Média (Próximas 2 semanas)
{}",
            if warning_count > 0 {
                format!("- [ ] Revisar problemas de qualidade de código")
            } else {
                "- [ ] Nenhuma ação necessária.".to_string()
            }
        ) + &format!(
            "

### 🟢 Prioridade Baixa (Próximo mês)
{}",
            if note_count > 0 {
                format!("- [ ] Implementar melhorias sugeridas")
            } else {
                "- [ ] Revisar futuras adições de código para garantir conformidade com práticas de segurança.".to_string()
            }
        )
    }

    /// Salva o relatório Markdown no arquivo de saída
    async fn save_markdown_report(&self, markdown_content: &str) -> crate::Result<()> {
        info!("Salvando relatório Markdown em: {:?}", self.config.output_file);
        
        // Cria diretório pai se não existir
        if let Some(parent) = self.config.output_file.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| crate::Error::Io(e))?;
        }
        
        // Salva o relatório
        std::fs::write(&self.config.output_file, markdown_content)
            .map_err(|e| crate::Error::Io(e))?;
        
        info!("Relatório Markdown salvo com sucesso em: {:?}", self.config.output_file);
        Ok(())
    }
    
    /// Gera o relatório final
    async fn generate_final_report(
        &self,
        codeql_analysis: &CodeQLAnalysis,
        chatgpt_analyses: &[ChatGPTAnalysis],
    ) -> crate::Result<()> {
        info!("Gerando relatório final em: {:?}", self.config.output_file);
        
        let report_content = crate::markdown::generate_report(
            codeql_analysis,
            chatgpt_analyses,
            &self.config,
        );
        
        // Cria diretório pai se não existir
        if let Some(parent) = self.config.output_file.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| crate::Error::Io(e))?;
        }
        
        // Salva o relatório
        std::fs::write(&self.config.output_file, report_content)
            .map_err(|e| crate::Error::Io(e))?;
        
        info!(
            "Relatório salvo com sucesso em: {:?}",
            self.config.output_file
        );
        
        // Exibe estatísticas finais
        self.display_final_statistics(codeql_analysis, chatgpt_analyses);
        
        Ok(())
    }
    
    /// Exibe estatísticas finais
    fn display_final_statistics(
        &self,
        codeql_analysis: &CodeQLAnalysis,
        chatgpt_analyses: &[ChatGPTAnalysis],
    ) {
        let total_findings = codeql_analysis.statistics.total_results;
        let files_with_issues = codeql_analysis.statistics.files_with_issues;
        
        let mut total_chatgpt_findings = 0;
        let mut high_severity = 0;
        let mut medium_severity = 0;
        let mut low_severity = 0;
        
        for analysis in chatgpt_analyses {
            total_chatgpt_findings += analysis.findings.len();
            
            for finding in &analysis.findings {
                match finding.severity.as_str() {
                    "high" => high_severity += 1,
                    "medium" => medium_severity += 1,
                    "low" => low_severity += 1,
                    _ => {}
                }
            }
        }
        
        info!("=== ESTATÍSTICAS FINAIS ===");
        info!("📊 CodeQL: {} achados em {} arquivos", total_findings, files_with_issues);
        info!("🤖 ChatGPT: {} achados detalhados", total_chatgpt_findings);
        info!("🔴 Alta severidade: {}", high_severity);
        info!("🟡 Média severidade: {}", medium_severity);
        info!("🟢 Baixa severidade: {}", low_severity);
        info!("📄 Relatório salvo em: {:?}", self.config.output_file);
        info!("==========================");
    }
}
