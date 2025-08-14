use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info};

/// Estrutura para uma mensagem do ChatGPT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// Estrutura para a requisição do ChatGPT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub temperature: f32,
    pub max_tokens: Option<u32>,
}

/// Estrutura para a resposta do ChatGPT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatChoice>,
    pub usage: Usage,
}

/// Estrutura para uma escolha da resposta
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatChoice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: Option<String>,
}

/// Estrutura para o uso de tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Cliente para integração com ChatGPT
pub struct ChatGPTClient {
    client: reqwest::Client,
    config: crate::config::Config,
    rate_limiter: tokio::sync::Mutex<()>,
}

impl ChatGPTClient {
    /// Cria um novo cliente ChatGPT
    pub fn new(config: crate::config::Config) -> crate::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .map_err(crate::Error::Http)?;

        Ok(Self {
            client,
            config,
            rate_limiter: tokio::sync::Mutex::new(()),
        })
    }

    /// Envia uma requisição para o ChatGPT
    pub async fn send_request(&self, messages: Vec<ChatMessage>) -> crate::Result<ChatResponse> {
        let _rate_limit_guard = self.rate_limiter.lock().await;

        // Rate limiting
        sleep(Duration::from_millis(
            1000 / self.config.rate_limit_rps as u64,
        ))
        .await;

        let request = ChatRequest {
            model: self.config.model.clone(),
            messages,
            temperature: self.config.temperature,
            max_tokens: Some(4000), // Limite razoável para respostas
        };

        debug!("Enviando requisição para ChatGPT: {:?}", request);

        let response = self
            .client
            .post(&self.config.openai_base_url)
            .header(
                "Authorization",
                format!("Bearer {}", self.config.openai_api_key),
            )
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                error!("Erro na requisição HTTP: {}", e);
                crate::Error::Http(e)
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Erro desconhecido".to_string());

            error!("Erro na resposta do ChatGPT: {} - {}", status, error_text);

            return match status.as_u16() {
                429 => Err(crate::Error::RateLimit),
                401 => Err(crate::Error::Authentication(
                    "Chave API inválida".to_string(),
                )),
                400 => Err(crate::Error::ChatGPT(format!(
                    "Requisição inválida: {}",
                    error_text
                ))),
                _ => Err(crate::Error::ChatGPT(format!(
                    "Erro HTTP {}: {}",
                    status, error_text
                ))),
            };
        }

        let chat_response: ChatResponse = response.json().await.map_err(|e| {
            error!("Erro ao deserializar resposta: {}", e);
            crate::Error::Http(e)
        })?;

        info!(
            "Resposta recebida do ChatGPT. Tokens usados: {}/{}",
            chat_response.usage.total_tokens, self.config.max_payload_tokens
        );

        Ok(chat_response)
    }

    /// Analisa as falhas do CodeQL com o ChatGPT e retorna relatório Markdown
    pub async fn analyze_codeql_findings(
        &self,
        _findings: &[crate::types::CodeQLResult],
        _code_snippets: &[(String, String)], // (file_path, code_content)
        full_file_content: &str,
        original_json: &str,
    ) -> crate::Result<String> {
        let system_message = ChatMessage {
            role: "system".to_string(),
            content: self.get_system_prompt().to_string(),
        };

        let user_message = ChatMessage {
            role: "user".to_string(),
            content: format!(
                r#"Analise o seguinte JSON do CodeQL e o arquivo de código para gerar um relatório completo de segurança.

JSON ORIGINAL DO CODEQL:
```json
{}
```

ARQUIVO DE CÓDIGO ANALISADO:
```python
{}
```

INSTRUÇÕES DE ORGANIZAÇÃO:
1. Analise o JSON do CodeQL para identificar os TIPOS de vulnerabilidades
2. AGRUPE vulnerabilidades do mesmo tipo - NÃO repita a mesma falha múltiplas vezes
3. Para cada tipo de vulnerabilidade, liste TODAS as linhas afetadas em uma única seção
4. Se há 7 falhas da mesma vulnerabilidade, mostre apenas 1 entrada com todas as 7 linhas
5. Use as informações do JSON (mensagens, severidade, localização) para explicar cada problema
6. Inclua as explicações e detalhes que o CodeQL fornece
7. Gere um relatório bem estruturado e organizado em Markdown
8. OBRIGATÓRIO: Para cada linha afetada, SEMPRE mostre o código real da linguagem (Python, JavaScript, etc.)
9. Use o código real do arquivo para mostrar as linhas problemáticas
10. Inclua recomendações baseadas nas informações do CodeQL

EXEMPLO DE ORGANIZAÇÃO:
- Se há 7 falhas de "Command Injection via subprocess", mostre apenas 1 seção com todas as 7 linhas
- Não crie 7 seções separadas para a mesma vulnerabilidade
- SEMPRE mostre o código real das linhas afetadas, não apenas números de linha"#,
                original_json, full_file_content
            ),
        };

        let messages = vec![system_message, user_message];

        let response = self.send_request(messages).await?;

        if let Some(choice) = response.choices.first() {
            let content = &choice.message.content;
            return Ok(content.clone());
        }

        Err(crate::Error::ChatGPT(
            "Nenhuma resposta válida recebida".to_string(),
        ))
    }

    /// Obtém o prompt do sistema
    fn get_system_prompt(&self) -> &str {
        "Você é um especialista em segurança de código e análise estática. Sua tarefa é analisar o JSON do CodeQL e gerar um relatório completo de segurança. IMPORTANTE: Você deve retornar um relatório completo formatado em MARKDOWN, não JSON. REGRAS DE ORGANIZAÇÃO: 1. NÃO REPITA a mesma vulnerabilidade múltiplas vezes. Se há várias ocorrências da mesma falha, agrupe-as em uma única entrada. 2. Para cada tipo de vulnerabilidade, liste TODAS as linhas afetadas em uma única seção. 3. Se há 7 falhas da mesma vulnerabilidade, mostre apenas 1 entrada com todas as 7 linhas. 4. Organize por TIPO de vulnerabilidade, não por linha individual. 5. OBRIGATÓRIO: Para cada linha afetada, SEMPRE mostre o código real da linguagem (Python, JavaScript, etc.) O relatório deve incluir: # Relatório de Segurança - Análise de Código com CodeQL ## Resumo Executivo [Análise geral baseada no JSON do CodeQL] ## Estatísticas [Baseadas nos dados do JSON - agrupe por tipo de vulnerabilidade] ## Achados Detalhados [Para cada TIPO de vulnerabilidade encontrado, inclua:] 1. **Vulnerabilidade: [tipo]** - **Problema:** [descrição do JSON] - **Severidade:** [do JSON] - **Linhas Afetadas:** [lista de todas as linhas] - **Código das Linhas:** ```[linguagem] [código real das linhas] ``` - **Explicação:** [baseada nas informações do JSON] ## Recomendações [Baseadas nas vulnerabilidades detectadas] ## Plano de Ação [Ações específicas para corrigir os problemas] REGRA IMPORTANTE: Agrupe vulnerabilidades do mesmo tipo, não repita a mesma falha múltiplas vezes, e SEMPRE mostre o código real das linhas afetadas."
    }
}
