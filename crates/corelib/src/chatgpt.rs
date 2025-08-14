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

INSTRUÇÕES ESPECÍFICAS:
1. Analise o JSON do CodeQL para identificar os TIPOS de vulnerabilidades
2. AGRUPE vulnerabilidades do mesmo tipo - NÃO repita a mesma falha múltiplas vezes
3. Para cada tipo de vulnerabilidade, liste TODAS as linhas afetadas em uma única seção
4. Use as informações do JSON (mensagens, severidade, localização) para explicar cada problema
5. Inclua as explicações e detalhes que o CodeQL fornece
6. OBRIGATÓRIO: Para cada linha afetada, SEMPRE mostre o código real da linguagem
7. Use o código real do arquivo para mostrar as linhas problemáticas
8. Inclua recomendações baseadas nas informações do CodeQL

FORMATO OBRIGATÓRIO:
- Use EXATAMENTE o formato especificado no prompt do sistema
- Inclua todos os títulos e seções: Resumo Executivo, Estatísticas, Achados Detalhados, Recomendações, Plano de Ação
- Para cada vulnerabilidade, use o formato: **Vulnerabilidade: [nome]**, **Problema:**, **Severidade:**, **Linhas Afetadas:**, **Código das Linhas:**, **Explicação:**
- SEMPRE mostre o código real das linhas afetadas, não apenas números de linha
- Agrupe vulnerabilidades do mesmo tipo em uma única entrada

RESTRIÇÕES IMPORTANTES:
- NÃO inclua seções de "Correções de Código Sugeridas" ou "Código Corrigido"
- MOSTRE APENAS o código original das linhas apontadas pelo CodeQL
- NÃO forneça sugestões de código corrigido ou alternativo
- Use EXATAMENTE as linhas de código que o CodeQL identificou como problemáticas"#,
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
        r#"Você é um especialista em segurança de código e análise estática. Sua tarefa é analisar o JSON do CodeQL e gerar um relatório completo de segurança.

IMPORTANTE: Você deve retornar um relatório completo formatado em MARKDOWN, seguindo EXATAMENTE este formato:

# Relatório de Segurança - Análise de Código com CodeQL

## Resumo Executivo
[Análise geral baseada no JSON do CodeQL - explique os tipos de vulnerabilidades encontradas e seu impacto]

## Estatísticas
[Baseadas nos dados do JSON - agrupe por tipo de vulnerabilidade, ex: "- Vulnerabilidades de Command Injection via subprocess: X ocorrências"]

## Achados Detalhados
[Para cada TIPO de vulnerabilidade encontrado, use este formato exato:]

1. **Vulnerabilidade: [nome exato da vulnerabilidade]**
   - **Problema:** [descrição exata do problema conforme o JSON]
   - **Severidade:** [severidade conforme o JSON]
   - **Linhas Afetadas:**
     - Linha X: [descrição da linha]
     - Linha Y: [descrição da linha]
     - [continue para todas as linhas afetadas]
   - **Código das Linhas:**
   ```[linguagem]
   [código real das linhas afetadas, exatamente como aparece no arquivo]
   ```
   - **Explicação:** [explicação baseada nas informações do JSON]

## Recomendações
[Baseadas nas vulnerabilidades detectadas - liste recomendações específicas]

## Plano de Ação
[Ações específicas para corrigir os problemas identificados]

REGRAS OBRIGATÓRIAS:
1. NÃO REPITA a mesma vulnerabilidade múltiplas vezes - agrupe todas as ocorrências do mesmo tipo
2. Para cada tipo de vulnerabilidade, liste TODAS as linhas afetadas em uma única seção
3. SEMPRE mostre o código real das linhas afetadas, não apenas números de linha
4. Use o formato exato mostrado acima, incluindo os títulos e estrutura
5. Organize por TIPO de vulnerabilidade, não por linha individual
6. Inclua as explicações e detalhes que o CodeQL fornece no JSON
7. NÃO inclua seções de "Correções de Código Sugeridas" ou "Código Corrigido"
8. MOSTRE APENAS o código original das linhas apontadas pelo CodeQL, sem sugestões de correção
9. Use EXATAMENTE as linhas de código que o CodeQL identificou como problemáticas"#
    }
}
