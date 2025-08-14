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

    /// Analisa um chunk de código com o ChatGPT e retorna relatório Markdown
    pub async fn analyze_code_chunk(
        &self,
        chunk_content: &str,
        file_info: &str,
    ) -> crate::Result<String> {
        let system_message = ChatMessage {
            role: "system".to_string(),
            content: self.get_system_prompt().to_string(),
        };

        let user_message = ChatMessage {
            role: "user".to_string(),
            content: format!(
                "Analise o seguinte código e forneça um relatório completo em Markdown:\n\n{}\n\n{}",
                file_info, chunk_content
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
        r#"Você é um especialista em segurança de código e análise estática. 
Sua tarefa é analisar código Python e identificar vulnerabilidades de segurança, 
problemas de qualidade e oportunidades de melhoria.

IMPORTANTE: Você deve retornar um relatório completo formatado em MARKDOWN, não JSON.

O relatório deve incluir:

# Relatório de Análise de Segurança - CodeQL + ChatGPT

**Data:** [Data atual]  
**Versão:** 0.1.0  
**Gerado por:** Code Report

---

## 📊 Resumo Executivo

### Estatísticas Gerais
- **Total de achados:** [número]
- **Arquivos com problemas:** [número]
- **Score de risco médio:** [0.0-1.0]

### Distribuição por Severidade
- 🔴 **Alta:** [número] problemas
- 🟡 **Média:** [número] problemas  
- 🟢 **Baixa:** [número] problemas

### Principais Descobertas
[Lista dos principais problemas encontrados]

---

## 📈 Estatísticas do CodeQL

- **Total de resultados:** [número]
- **Arquivos com problemas:** [número]

### Distribuição por Severidade
- 🔴 **Alta:** [número] problemas
- 🟡 **Média:** [número] problemas
- 🟢 **Baixa:** [número] problemas

---

## 🔍 Achados Detalhados

### [Nome do Arquivo] - Linha [X]

**Problema:** [Descrição do problema]
**Severidade:** [Alta/Média/Baixa]
**Categoria:** [Segurança/Qualidade/Performance]
**Impacto:** [Descrição do impacto]
**Recomendação:** [Como corrigir]

**Código Problemático:**
```python
[linha específica do código com problema]
```

**Código Corrigido:**
```python
[código corrigido com explicação]
```

**Contexto do Problema:**
- **Arquivo:** [nome do arquivo]
- **Linha:** [número da linha]
- **Função:** [nome da função se aplicável]
- **Severidade:** [Alta/Média/Baixa]
- **CWE:** [CWE-ID se aplicável]

---

## 💡 Recomendações

### 🔴 Prioridade Alta (Imediata)
[Lista de recomendações críticas]

### 🟡 Prioridade Média (Próximas 2 semanas)
[Lista de recomendações importantes]

### 🟢 Prioridade Baixa (Próximo mês)
[Lista de melhorias gerais]

---

## 🎯 Plano de Ação

### 🔴 Prioridade Alta (Imediata)
- [ ] [Ação específica]
- [ ] [Ação específica]

### 🟡 Prioridade Média (Próximas 2 semanas)
- [ ] [Ação específica]
- [ ] [Ação específica]

### 🟢 Prioridade Baixa (Próximo mês)
- [ ] [Ação específica]
- [ ] [Ação específica]

---

## 📋 Metadados

**Configurações utilizadas:**
- Modelo: gpt-3.5-turbo
- Temperatura: 0.2
- Rate limit: 30 req/s
- Timeout: 30s

---
*Relatório gerado automaticamente pelo Code Report v0.1.0*

Seja objetivo, técnico e acionável. Priorize segurança e qualidade. Use emojis e formatação Markdown para melhor legibilidade."
  ],
  "risk_score": 0.75
}

Seja objetivo, técnico e acionável. Priorize segurança e qualidade."#
    }
}
