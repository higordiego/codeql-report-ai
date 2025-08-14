use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Estrutura para representar o formato SARIF do CodeQL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    pub version: String,
    pub runs: Vec<Run>,
}

/// Estrutura para representar uma execução do CodeQL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub tool: Tool,
    pub results: Vec<Result>,
}

/// Estrutura para representar a ferramenta
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub driver: Driver,
}

/// Estrutura para representar o driver da ferramenta
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Driver {
    pub name: String,
    pub organization: Option<String>,
    #[serde(rename = "semanticVersion")]
    pub semantic_version: Option<String>,
}

/// Estrutura para representar um resultado SARIF
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Result {
    #[serde(rename = "ruleId")]
    pub rule_id: Option<String>,
    pub level: Option<String>,
    pub message: Message,
    pub locations: Vec<Location>,
    #[serde(flatten)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Estrutura para representar uma mensagem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub text: String,
}

/// Estrutura para representar uma localização
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    #[serde(rename = "physicalLocation")]
    pub physical_location: PhysicalLocation,
}

/// Estrutura para representar uma localização física
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: ArtifactLocation,
    pub region: Option<Region>,
}

/// Estrutura para representar uma localização de artefato
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactLocation {
    pub uri: String,
}

/// Estrutura para representar uma região
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    #[serde(rename = "startLine")]
    pub start_line: Option<u32>,
    #[serde(rename = "startColumn")]
    pub start_column: Option<u32>,
    #[serde(rename = "endLine")]
    pub end_line: Option<u32>,
    #[serde(rename = "endColumn")]
    pub end_column: Option<u32>,
}






