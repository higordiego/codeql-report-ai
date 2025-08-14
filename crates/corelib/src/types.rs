//! Tipos e estruturas de dados principais

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Resultado de uma análise CodeQL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLResult {
    pub rule_id: String,
    pub message: String,
    pub severity: String,
    pub file_path: String,
    pub line_number: Option<u32>,
    pub column_number: Option<u32>,
    pub end_line_number: Option<u32>,
    pub end_column_number: Option<u32>,
}

/// Arquivo de código analisado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeFile {
    pub path: PathBuf,
    pub content: String,
    pub hash: String,
    pub size: usize,
}

/// Análise completa do CodeQL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLAnalysis {
    pub results: Vec<CodeQLResult>,
    pub files: Vec<CodeFile>,
    pub statistics: AnalysisStatistics,
    pub metadata: AnalysisMetadata,
}

/// Estatísticas da análise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStatistics {
    pub total_results: usize,
    pub files_with_issues: usize,
    pub high_severity_count: usize,
    pub medium_severity_count: usize,
    pub low_severity_count: usize,
}

/// Metadados da análise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetadata {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub tool_version: String,
    pub project_name: Option<String>,
}

/// Análise do ChatGPT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatGPTAnalysis {
    pub findings: Vec<Finding>,
    pub recommendations: Vec<Recommendation>,
    pub summary: String,
    pub confidence_score: f32,
}

/// Achado de segurança
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub file_path: Option<String>,
    pub line_number: Option<u32>,
    pub code_snippet: Option<String>,
    pub impact: String,
    pub remediation: String,
}

/// Recomendação de melhoria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub title: String,
    pub description: String,
    pub priority: String,
    pub effort: String,
    pub impact: String,
    pub steps: Vec<String>,
}

/// Chunk de código para análise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    pub id: String,
    pub file_path: PathBuf,
    pub content: String,
    pub start_line: usize,
    pub end_line: usize,
    pub token_count: usize,
}

/// Arquivo chunkado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkFile {
    pub path: PathBuf,
    pub chunks: Vec<Chunk>,
    pub total_tokens: usize,
}

impl Default for CodeQLAnalysis {
    fn default() -> Self {
        Self {
            results: Vec::new(),
            files: Vec::new(),
            statistics: AnalysisStatistics {
                total_results: 0,
                files_with_issues: 0,
                high_severity_count: 0,
                medium_severity_count: 0,
                low_severity_count: 0,
            },
            metadata: AnalysisMetadata {
                timestamp: chrono::Utc::now(),
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                project_name: None,
            },
        }
    }
}

impl CodeQLAnalysis {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update_statistics(&mut self) {
        self.statistics.total_results = self.results.len();

        let mut files_with_issues = std::collections::HashSet::new();
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;

        for result in &self.results {
            files_with_issues.insert(result.file_path.clone());

            match result.severity.to_lowercase().as_str() {
                "error" | "high" => high_count += 1,
                "warning" | "medium" => medium_count += 1,
                "note" | "low" => low_count += 1,
                _ => low_count += 1,
            }
        }

        self.statistics.files_with_issues = files_with_issues.len();
        self.statistics.high_severity_count = high_count;
        self.statistics.medium_severity_count = medium_count;
        self.statistics.low_severity_count = low_count;
    }

    pub fn get_files_with_issues(&self) -> Vec<&str> {
        let mut files = std::collections::HashSet::new();
        for result in &self.results {
            files.insert(result.file_path.as_str());
        }
        files.into_iter().collect()
    }

    pub fn filter_by_severity(&self, severity: &str) -> Vec<&CodeQLResult> {
        self.results
            .iter()
            .filter(|result| result.severity.to_lowercase() == severity.to_lowercase())
            .collect()
    }

    pub fn filter_by_category(&self, category: &str) -> Vec<&CodeQLResult> {
        self.results
            .iter()
            .filter(|result| result.rule_id.contains(category))
            .collect()
    }

    pub fn get_file_for_result(&self, result: &CodeQLResult) -> Option<&CodeFile> {
        self.files
            .iter()
            .find(|file| file.path.to_string_lossy() == result.file_path)
    }

    pub fn from_json_file(path: &str) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path).map_err(crate::Error::Io)?;

        Self::from_json(&content)
    }

    pub fn from_json(json_content: &str) -> crate::Result<Self> {
        // Tenta primeiro como SARIF
        if let Ok(sarif_report) = serde_json::from_str::<crate::codeql::SarifReport>(json_content) {
            return Self::from_sarif(sarif_report);
        }

        // Fallback para formato simples (array de resultados)
        if let Ok(results) = serde_json::from_str::<Vec<CodeQLResult>>(json_content) {
            let mut analysis = Self::new();
            analysis.results = results;
            analysis.update_statistics();
            return Ok(analysis);
        }

        // Se não conseguir parsear, retorna erro
        Err(crate::Error::Config(
            "Formato JSON não reconhecido".to_string(),
        ))
    }

    pub fn from_sarif(sarif_report: crate::codeql::SarifReport) -> crate::Result<Self> {
        let mut analysis = Self::new();

        for run in sarif_report.runs {
            for result in run.results {
                let codeql_result = Self::convert_sarif_result(result);
                analysis.results.push(codeql_result);
            }
        }

        analysis.update_statistics();
        Ok(analysis)
    }

    fn convert_sarif_result(sarif_result: crate::codeql::Result) -> CodeQLResult {
        let location = sarif_result
            .locations
            .first()
            .and_then(|loc| loc.physical_location.region.as_ref());

        // Normaliza o caminho do arquivo
        let file_path = sarif_result
            .locations
            .first()
            .map(|loc| {
                let uri = &loc.physical_location.artifact_location.uri;
                // Remove prefixos como "file://" e normaliza o caminho
                if uri.starts_with("file://") {
                    uri.trim_start_matches("file://").to_string()
                } else {
                    // Para caminhos relativos, adiciona "./" se necessário
                    if uri.starts_with("./") || uri.starts_with("/") {
                        uri.to_string()
                    } else {
                        // Para arquivos simples como "main.py", adiciona "./"
                        format!("./{}", uri)
                    }
                }
            })
            .unwrap_or_else(|| "unknown".to_string());

        CodeQLResult {
            rule_id: sarif_result
                .rule_id
                .unwrap_or_else(|| "unknown".to_string()),
            message: sarif_result.message.text,
            severity: sarif_result.level.unwrap_or_else(|| "warning".to_string()),
            file_path,
            line_number: location.and_then(|reg| reg.start_line),
            column_number: location.and_then(|reg| reg.start_column),
            end_line_number: location.and_then(|reg| reg.end_line),
            end_column_number: location.and_then(|reg| reg.end_column),
        }
    }
}

impl Chunk {
    pub fn new(
        id: String,
        file_path: PathBuf,
        content: String,
        start_line: usize,
        end_line: usize,
        token_count: usize,
    ) -> Self {
        Self {
            id,
            file_path,
            content,
            start_line,
            end_line,
            token_count,
        }
    }

    pub fn generate_file_info(&self) -> String {
        format!(
            "## Arquivo: {}\n- Linhas: {}-{}\n- Tokens: {}\n\n",
            self.file_path.display(),
            self.start_line,
            self.end_line,
            self.token_count
        )
    }

    pub fn generate_content(&self) -> String {
        format!(
            ">>> BEGIN FILE {}\n{}\n>>> END FILE {}\n",
            self.file_path.display(),
            self.content,
            self.file_path.display()
        )
    }
}
