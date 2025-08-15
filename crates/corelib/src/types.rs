//! Tipos e estruturas de dados principais

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Represents a CodeQL analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLAnalysis {
    pub runs: Vec<CodeQLRun>,
}

impl CodeQLAnalysis {
    /// Gets all results from all runs
    pub fn results(&self) -> Vec<CodeQLResult> {
        self.runs
            .iter()
            .flat_map(|run| run.results.clone())
            .collect()
    }
}

/// Represents a CodeQL run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLRun {
    pub results: Vec<CodeQLResult>,
}

/// Represents a single CodeQL result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "ruleIndex")]
    pub rule_index: Option<u32>,
    pub rule: Option<CodeQLRule>,
    pub message: CodeQLMessage,
    pub locations: Vec<CodeQLLocation>,
    #[serde(rename = "partialFingerprints")]
    pub partial_fingerprints: Option<CodeQLFingerprints>,
    // Campo adicional para compatibilidade - usar default se não existir
    #[serde(default = "default_level")]
    pub level: String,
}

fn default_level() -> String {
    "error".to_string()
}

/// Represents a CodeQL rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLRule {
    pub id: String,
    pub index: u32,
}

/// Represents a CodeQL message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLMessage {
    pub text: String,
}

impl std::fmt::Display for CodeQLMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.text)
    }
}

/// Represents CodeQL fingerprints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLFingerprints {
    #[serde(rename = "primaryLocationLineHash")]
    pub primary_location_line_hash: Option<String>,
    #[serde(rename = "primaryLocationStartColumnFingerprint")]
    pub primary_location_start_column_fingerprint: Option<String>,
}

/// Represents a location in the code where a vulnerability was found
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: Option<CodeQLPhysicalLocation>,
}

/// Represents the physical location details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: CodeQLArtifactLocation,
    pub region: CodeQLRegion,
}

/// Represents the artifact (file) location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLArtifactLocation {
    pub uri: String,
    #[serde(rename = "uriBaseId")]
    pub uri_base_id: Option<String>,
    pub index: Option<u32>,
}

/// Represents a region in the code (line numbers)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLRegion {
    #[serde(rename = "startLine")]
    pub start_line: u32,
    #[serde(rename = "endLine")]
    pub end_line: Option<u32>,
    #[serde(rename = "startColumn")]
    pub start_column: Option<u32>,
    #[serde(rename = "endColumn")]
    pub end_column: Option<u32>,
}

/// Represents different report levels
#[derive(Debug, Clone, PartialEq)]
pub enum ReportLevel {
    Easy,
    Medium,
    Advanced,
}

impl FromStr for ReportLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "easy" => Ok(ReportLevel::Easy),
            "medium" => Ok(ReportLevel::Medium),
            "advanced" => Ok(ReportLevel::Advanced),
            _ => Err(format!("Invalid report level: {}", s)),
        }
    }
}

/// Represents a chat message for ChatGPT API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// Represents a chat request to ChatGPT API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub temperature: f32,
    pub max_tokens: u32,
}

/// Represents a chat response from ChatGPT API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatChoice>,
    pub usage: Usage,
}

/// Represents a choice in the chat response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatChoice {
    pub index: u32,
    pub message: Option<ChatMessage>,
    pub finish_reason: Option<String>,
}

/// Represents token usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}
