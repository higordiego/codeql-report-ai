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
- Inclua apenas os títulos e seções: Resumo Executivo, Estatísticas, Achados Detalhados
- Para cada vulnerabilidade, use o formato: **Vulnerabilidade: [nome]**, **Problema:**, **Severidade:**, **Linhas Afetadas:**, **Código das Linhas:**, **Explicação:**
- SEMPRE mostre o código real das linhas afetadas, não apenas números de linha
- Agrupe vulnerabilidades do mesmo tipo em uma única entrada

RESTRIÇÕES IMPORTANTES:
- NÃO inclua seções de "Correções de Código Sugeridas" ou "Código Corrigido"
- NÃO inclua seções de "Recomendações" ou "Plano de Ação"
- MOSTRE APENAS o código original das linhas apontadas pelo CodeQL
- NÃO forneça sugestões de código corrigido ou alternativo
- Use EXATAMENTE as linhas de código que o CodeQL identificou como problemáticas
- NÃO inclua emojis ou formatação colorida no relatório"#,
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
        r#"Entendi, você quer um **prompt definitivo**, bem claro e “amigável” para que qualquer LLM sempre gere relatórios **exatamente** nesse formato que você mostrou — com Resumo Executivo, Estatísticas, Achados Detalhados, Recomendações e Plano de Ação.

Segue a versão reformulada e simplificada para ficar 100% acessível e objetiva:

---

**PROMPT DEFINITIVO — RELATÓRIO DE SEGURANÇA (CodeQL)**

Você é um especialista em segurança de código e análise estática.
Sua tarefa é analisar o **JSON do CodeQL** e gerar um relatório **exatamente** no formato abaixo, em **MARKDOWN**.

---

# Relatório de Segurança - Análise de Código com CodeQL

## Resumo Executivo

\[Explique de forma clara as vulnerabilidades encontradas, os arquivos afetados e o impacto potencial.]

## Estatísticas

\[Liste o total de ocorrências agrupadas por tipo de vulnerabilidade.]
Exemplo:

* Vulnerabilidades de Command Injection via subprocess: 7 ocorrências

## Achados Detalhados

Para cada tipo de vulnerabilidade, siga este formato:

1. **Vulnerabilidade:** \[nome exato]

   * **Problema:** \[descrição conforme JSON]
   * **Severidade:** \[nível do JSON]
   * **Linhas Afetadas:**

     * Linha X: `[código da linha exata]`
     * Linha Y: `[código da linha exata]`
     * \[listar todas]
   * **Código das Linhas:**

   ```[linguagem]
   [código original exato]
   ```

   * **Explicação:** \[detalhamento técnico com base no JSON]

## Recomendações

\[Liste recomendações práticas para prevenir e corrigir as falhas.]

## Plano de Ação

\[Liste passos claros para corrigir as vulnerabilidades.]

---

### REGRAS FIXAS:

1. **Agrupar** todas as ocorrências do mesmo tipo de vulnerabilidade em **uma única entrada**.
2. **Sempre** incluir o código original exatamente como aparece no arquivo.
3. **Seguir rigorosamente** a estrutura de títulos e subtítulos.
4. **Sempre** incluir Recomendações e Plano de Ação.
5. Não usar emojis, cores ou formatação extra além do Markdown básico.

---

Se quiser, posso já te devolver **uma versão “blindada”** desse prompt otimizada para LLMs, com instruções reforçadas para impedir que o modelo quebre o formato. Isso garantiria que o relatório venha **sempre igual**, sem variações.

Quer que eu já te prepare essa versão?
"#
    }
}
