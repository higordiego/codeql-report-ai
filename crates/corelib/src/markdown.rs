use crate::types::*;
use chrono::Utc;
use std::collections::HashMap;

/// Gera um relatório completo em Markdown
pub fn generate_report(
    codeql_analysis: &CodeQLAnalysis,
    chatgpt_analyses: &[ChatGPTAnalysis],
    config: &crate::config::Config,
) -> String {
    let mut report = String::new();

    // Cabeçalho
    report.push_str(&generate_header());

    // Resumo executivo
    report.push_str(&generate_executive_summary(
        codeql_analysis,
        chatgpt_analyses,
    ));

    // Estatísticas do CodeQL
    report.push_str(&generate_codeql_statistics(&codeql_analysis.statistics));

    // Achados detalhados
    report.push_str(&generate_findings_section(
        codeql_analysis,
        chatgpt_analyses,
    ));

    // Metadados
    report.push_str(&generate_metadata(config));

    report
}

/// Gera o cabeçalho do relatório
fn generate_header() -> String {
    format!(
        r#"# Relatório de Análise de Segurança - CodeQL + ChatGPT

**Data:** {date}  
**Versão:** {version}  
**Gerado por:** CodeQL ChatGPT Analyzer

---

"#,
        date = Utc::now().format("%d/%m/%Y %H:%M:%S UTC"),
        version = crate::VERSION
    )
}

/// Gera o resumo executivo
fn generate_executive_summary(
    codeql_analysis: &CodeQLAnalysis,
    chatgpt_analyses: &[ChatGPTAnalysis],
) -> String {
    let total_findings = codeql_analysis.statistics.total_results;
    let files_with_issues = codeql_analysis.statistics.files_with_issues;

    let mut severity_counts = HashMap::new();
    for analysis in chatgpt_analyses {
        for finding in &analysis.findings {
            *severity_counts.entry(finding.severity.clone()).or_insert(0) += 1;
        }
    }

    let high_severity = severity_counts.get("high").unwrap_or(&0);
    let medium_severity = severity_counts.get("medium").unwrap_or(&0);
    let low_severity = severity_counts.get("low").unwrap_or(&0);

    let avg_risk_score: f32 = chatgpt_analyses
        .iter()
        .map(|a| a.confidence_score)
        .sum::<f32>()
        / chatgpt_analyses.len() as f32;

    format!(
        r#"## 📊 Resumo Executivo

### Estatísticas Gerais
- **Total de achados:** {total_findings}
- **Arquivos com problemas:** {files_with_issues}
- **Score de risco médio:** {risk_score:.2}/1.0

### Distribuição por Severidade
- 🔴 **Alta:** {high} problemas
- 🟡 **Média:** {medium} problemas  
- 🟢 **Baixa:** {low} problemas

### Principais Descobertas
{main_findings}

---

"#,
        total_findings = total_findings,
        files_with_issues = files_with_issues,
        risk_score = avg_risk_score,
        high = high_severity,
        medium = medium_severity,
        low = low_severity,
        main_findings = generate_main_findings_summary(chatgpt_analyses)
    )
}

/// Gera resumo dos principais achados
fn generate_main_findings_summary(chatgpt_analyses: &[ChatGPTAnalysis]) -> String {
    let mut all_findings = Vec::new();

    for analysis in chatgpt_analyses {
        for finding in &analysis.findings {
            all_findings.push(finding);
        }
    }

    // Ordena por severidade
    all_findings.sort_by(|a, b| {
        let severity_order = |s: &str| match s {
            "high" => 0,
            "medium" => 1,
            "low" => 2,
            _ => 3,
        };
        severity_order(&a.severity).cmp(&severity_order(&b.severity))
    });

    let mut summary = String::new();

    // Top 5 achados mais críticos
    for (i, finding) in all_findings.iter().take(5).enumerate() {
        let severity_icon = match finding.severity.as_str() {
            "high" => "🔴",
            "medium" => "🟡",
            "low" => "🟢",
            _ => "⚪",
        };

        summary.push_str(&format!(
            "{}. {} **{}** - {}\n",
            i + 1,
            severity_icon,
            finding.title,
            finding.file_path.as_ref().unwrap_or(&"unknown".to_string())
        ));
    }

    summary
}

/// Gera estatísticas do CodeQL
fn generate_codeql_statistics(stats: &AnalysisStatistics) -> String {
    let mut section = String::new();
    section.push_str("## 📈 Estatísticas do CodeQL\n\n");

    section.push_str(&format!(
        "- **Total de resultados:** {}\n",
        stats.total_results
    ));
    section.push_str(&format!(
        "- **Arquivos com problemas:** {}\n",
        stats.files_with_issues
    ));
    section.push_str(&format!(
        "- **Total de arquivos com problemas:** {}\n\n",
        stats.files_with_issues
    ));

    // Distribuição por severidade
    section.push_str("### Distribuição por Severidade\n\n");
    section.push_str(&format!(
        "- 🔴 **Alta:** {} problemas\n",
        stats.high_severity_count
    ));
    section.push_str(&format!(
        "- 🟡 **Média:** {} problemas\n",
        stats.medium_severity_count
    ));
    section.push_str(&format!(
        "- 🟢 **Baixa:** {} problemas\n",
        stats.low_severity_count
    ));
    section.push('\n');

    section.push_str("---\n\n");
    section
}

/// Gera seção de achados detalhados
fn generate_findings_section(
    _codeql_analysis: &CodeQLAnalysis,
    chatgpt_analyses: &[ChatGPTAnalysis],
) -> String {
    let mut section = String::new();
    section.push_str("## 🔍 Achados Detalhados\n\n");

    // Agrupa achados por arquivo
    let mut findings_by_file: HashMap<String, Vec<&Finding>> = HashMap::new();

    for analysis in chatgpt_analyses {
        for finding in &analysis.findings {
            findings_by_file
                .entry(
                    finding
                        .file_path
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                )
                .or_default()
                .push(finding);
        }
    }

    for (file, findings) in findings_by_file {
        section.push_str(&format!("### 📄 {}\n\n", file));

        for finding in findings {
            let severity_icon = match finding.severity.as_str() {
                "high" => "🔴",
                "medium" => "🟡",
                "low" => "🟢",
                _ => "⚪",
            };

            section.push_str(&format!("#### {} {}\n\n", severity_icon, finding.title));

            if let Some(line) = finding.line_number {
                section.push_str(&format!("**Localização:** Linha {}\n\n", line));
            }

            section.push_str(&format!("**Categoria:** {}\n\n", finding.category));
            section.push_str(&format!("**Descrição:** {}\n\n", finding.description));
            section.push_str(&format!("**Recomendação:** {}\n\n", finding.remediation));

            section.push_str("---\n\n");
        }
    }

    section
}

/// Gera metadados do relatório
fn generate_metadata(config: &crate::config::Config) -> String {
    format!(
        r#"## 📋 Metadados

**Configurações utilizadas:**
- Modelo: {}
- Temperatura: {}
- Rate limit: {} req/s
- Timeout: {}s
- Tamanho máximo de arquivo: {} bytes
- Limite de tokens: {}

**Arquivo de saída:** {}

---
*Relatório gerado automaticamente pelo CodeQL ChatGPT Analyzer v{}*
"#,
        config.model,
        config.temperature,
        config.rate_limit_rps,
        config.timeout_seconds,
        config.max_file_bytes,
        config.max_payload_tokens,
        config.output_file.display(),
        crate::VERSION
    )
}
