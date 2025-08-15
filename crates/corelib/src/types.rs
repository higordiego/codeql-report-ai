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
    pub rule_id: String,
    pub level: String,
    pub message: String,
    pub locations: Vec<CodeQLLocation>,
}

/// Represents a location in the code where a vulnerability was found
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLLocation {
    pub physical_location: Option<CodeQLPhysicalLocation>,
}

/// Represents the physical location details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLPhysicalLocation {
    pub artifact_location: CodeQLArtifactLocation,
    pub region: CodeQLRegion,
}

/// Represents the artifact (file) location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLArtifactLocation {
    pub uri: String,
}

/// Represents a region in the code (line numbers)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQLRegion {
    pub start_line: u32,
    pub end_line: Option<u32>,
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
