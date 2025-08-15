use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Entidade principal para representar um resultado do CodeQL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLResult {
    /// Caminho do arquivo onde a falha foi encontrada
    pub file: String,
    
    /// Linha onde a falha foi encontrada
    pub line: Option<u32>,
    
    /// Coluna onde a falha foi encontrada
    pub column: Option<u32>,
    
    /// End line da falha
    pub end_line: Option<u32>,
    
    /// End column da falha
    pub end_column: Option<u32>,
    
    /// Mensagem da falha
    pub message: String,
    
    /// Severidade da falha
    pub severity: Option<String>,
    
    /// Categoria da falha
    pub category: Option<String>,
    
    /// CWE (Common Weakness Enumeration) se disponível
    pub cwe: Option<String>,
    
    /// Descrição detalhada da falha
    pub description: Option<String>,
    
    /// Sugestões de correção
    pub suggestions: Option<Vec<String>>,
    
    /// Metadados adicionais
    #[serde(flatten)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Entidade para representar um arquivo de código
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeFile {
    /// Caminho relativo do arquivo
    pub path: std::path::PathBuf,
    
    /// Conteúdo do arquivo
    pub content: String,
    
    /// Hash SHA256 do arquivo
    pub hash: String,
    
    /// Número de linhas
    pub line_count: usize,
    
    /// Tamanho em bytes
    pub size_bytes: usize,
}

/// Entidade para representar uma análise de CodeQL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLAnalysis {
    /// Resultados encontrados
    pub results: Vec<CodeQLResult>,
    
    /// Arquivos analisados
    pub files: Vec<CodeFile>,
    
    /// Estatísticas da análise
    pub statistics: AnalysisStatistics,
    
    /// Metadados da execução
    pub metadata: AnalysisMetadata,
}

/// Estatísticas da análise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStatistics {
    /// Total de resultados
    pub total_results: usize,
    
    /// Resultados por severidade
    pub results_by_severity: HashMap<String, usize>,
    
    /// Resultados por categoria
    pub results_by_category: HashMap<String, usize>,
    
    /// Arquivos únicos com falhas
    pub files_with_issues: usize,
    
    /// Total de arquivos analisados
    pub total_files: usize,
}

/// Metadados da análise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetadata {
    /// Data e hora da análise
    pub timestamp: chrono::DateTime<chrono::Utc>,
    
    /// Versão do CodeQL usada
    pub codeql_version: Option<String>,
    
    /// Queries executadas
    pub queries: Vec<String>,
    
    /// Tempo de execução em segundos
    pub execution_time_seconds: Option<f64>,
}

/// Entidade para representar uma análise do ChatGPT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatGPTAnalysis {
    pub findings: Vec<Finding>,
    pub summary: String,
    pub recommendations: Vec<Recommendation>,
    pub risk_score: f32,
}

/// Entidade para representar um achado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub file: String,
    pub line: Option<u32>,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub cwe: Option<String>,
}

/// Entidade para representar uma recomendação
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: String,
    pub title: String,
    pub description: String,
    pub action_items: Vec<String>,
    pub estimated_effort: String,
}

/// Entidade para representar um chunk de arquivos
#[derive(Debug, Clone)]
pub struct Chunk {
    pub files: Vec<ChunkFile>,
    pub total_size: usize,
}

/// Entidade para representar um arquivo dentro de um chunk
#[derive(Debug, Clone)]
pub struct ChunkFile {
    pub path: std::path::PathBuf,
    pub content: String,
    pub hash: String,
    pub line_count: usize,
}

// Implementações padrão
impl Default for CodeQLAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeQLAnalysis {
    /// Cria uma nova análise vazia
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            files: Vec::new(),
            statistics: AnalysisStatistics {
                total_results: 0,
                results_by_severity: HashMap::new(),
                results_by_category: HashMap::new(),
                files_with_issues: 0,
                total_files: 0,
            },
            metadata: AnalysisMetadata {
                timestamp: chrono::Utc::now(),
                codeql_version: None,
                queries: Vec::new(),
                execution_time_seconds: None,
            },
        }
    }
    
    /// Carrega resultados do CodeQL de um arquivo JSON
    pub fn from_json_file<P: AsRef<std::path::Path>>(path: P) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::Error::FileNotFound(e.to_string()))?;
        
        Self::from_json(&content)
    }
    
    /// Carrega resultados do CodeQL de uma string JSON
    pub fn from_json(json_content: &str) -> crate::Result<Self> {
        // Tenta primeiro o formato SARIF
        if let Ok(sarif_report) = serde_json::from_str::<crate::codeql::SarifReport>(json_content) {
            return Self::from_sarif(sarif_report);
        }
        
        // Se não for SARIF, tenta o formato simples
        let results: Vec<CodeQLResult> = serde_json::from_str(json_content)
            .map_err(|e| crate::Error::Json(e))?;
        
        let mut analysis = Self::new();
        analysis.results = results;
        analysis.update_statistics();
        
        Ok(analysis)
    }
    
    /// Converte relatório SARIF para análise CodeQL
    pub fn from_sarif(sarif_report: crate::codeql::SarifReport) -> crate::Result<Self> {
        let mut analysis = Self::new();
        
        for run in sarif_report.runs {
            for result in run.results {
                let codeql_result = Self::convert_sarif_result(result)?;
                analysis.results.push(codeql_result);
            }
        }
        
        analysis.update_statistics();
        Ok(analysis)
    }
    
    /// Converte um resultado SARIF para formato CodeQL
    fn convert_sarif_result(sarif_result: crate::codeql::Result) -> crate::Result<CodeQLResult> {
        if sarif_result.locations.is_empty() {
            return Err(crate::Error::CodeQL("Resultado SARIF sem localização".to_string()));
        }
        
        let location = &sarif_result.locations[0];
        let artifact_uri = &location.physical_location.artifact_location.uri;
        
        // Remove prefixo file:// se presente
        let file_path = if artifact_uri.starts_with("file://") {
            &artifact_uri[7..]
        } else {
            artifact_uri
        };
        
        let region = &location.physical_location.region;
        
        Ok(CodeQLResult {
            file: file_path.to_string(),
            line: Some(region.start_line),
            column: region.start_column,
            end_line: region.end_line,
            end_column: region.end_column,
            message: sarif_result.message.text,
            severity: Some("error".to_string()), // SARIF não tem level, usar default
            category: Some(sarif_result.rule_id),
            cwe: None, // SARIF não tem CWE por padrão
            description: None,
            suggestions: None,
            metadata: HashMap::new(), // SARIF não tem metadata neste nível
        })
    }
    
    /// Atualiza as estatísticas da análise
    pub fn update_statistics(&mut self) {
        let mut severity_counts = HashMap::new();
        let mut category_counts = HashMap::new();
        let mut files_with_issues = std::collections::HashSet::new();
        
        for result in &self.results {
            // Conta por severidade
            let severity = result.severity.as_deref().unwrap_or("unknown");
            *severity_counts.entry(severity.to_string()).or_insert(0) += 1;
            
            // Conta por categoria
            if let Some(category) = &result.category {
                *category_counts.entry(category.clone()).or_insert(0) += 1;
            }
            
            // Arquivos com falhas
            files_with_issues.insert(result.file.clone());
        }
        
        self.statistics = AnalysisStatistics {
            total_results: self.results.len(),
            results_by_severity: severity_counts,
            results_by_category: category_counts,
            files_with_issues: files_with_issues.len(),
            total_files: self.files.len(),
        };
    }
    
    /// Obtém arquivos únicos que contêm falhas
    pub fn get_files_with_issues(&self) -> std::collections::HashSet<&str> {
        self.results
            .iter()
            .map(|r| r.file.as_str())
            .collect()
    }
    
    /// Filtra resultados por severidade
    pub fn filter_by_severity(&self, severity: &str) -> Vec<&CodeQLResult> {
        self.results
            .iter()
            .filter(|r| r.severity.as_deref() == Some(severity))
            .collect()
    }
    
    /// Filtra resultados por categoria
    pub fn filter_by_category(&self, category: &str) -> Vec<&CodeQLResult> {
        self.results
            .iter()
            .filter(|r| r.category.as_deref() == Some(category))
            .collect()
    }
    
    /// Obtém o arquivo de código correspondente a um resultado
    pub fn get_file_for_result(&self, result: &CodeQLResult) -> Option<&CodeFile> {
        self.files
            .iter()
            .find(|f| f.path.to_string_lossy() == result.file)
    }
}

impl Default for Chunk {
    fn default() -> Self {
        Self::new()
    }
}

impl Chunk {
    /// Cria um novo chunk vazio
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            total_size: 0,
        }
    }
}
