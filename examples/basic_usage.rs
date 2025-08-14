use codeql_chatgpt_analyzer::prelude::*;

/// Exemplo básico de uso da biblioteca CodeQL ChatGPT Analyzer
#[tokio::main]
async fn main() -> Result<()> {
    // Configura logging
    tracing_subscriber::fmt::init();
    
    println!("🚀 Exemplo básico de uso do CodeQL ChatGPT Analyzer");
    
    // 1. Carrega configuração do ambiente
    let config = match Config::from_env() {
        Ok(config) => {
            println!("✅ Configuração carregada com sucesso");
            config
        }
        Err(e) => {
            eprintln!("❌ Erro ao carregar configuração: {}", e);
            eprintln!("💡 Configure as variáveis de ambiente necessárias");
            return Err(e);
        }
    };
    
    // 2. Valida a configuração
    if let Err(e) = config.validate() {
        eprintln!("❌ Configuração inválida: {}", e);
        return Err(e);
    }
    
    println!("📁 Projeto: {:?}", config.project_root);
    println!("🤖 Modelo: {}", config.model);
    println!("📄 Saída: {:?}", config.output_file);
    
    // 3. Cria o analisador
    let analyzer = match CodeQLAnalyzer::new(config.clone()) {
        Ok(analyzer) => {
            println!("✅ Analisador criado com sucesso");
            analyzer
        }
        Err(e) => {
            eprintln!("❌ Erro ao criar analisador: {}", e);
            return Err(e);
        }
    };
    
    // 4. Executa a análise
    println!("🔍 Iniciando análise...");
    
    match analyzer.analyze("examples/sample-codeql-results.json").await {
        Ok(()) => {
            println!("✅ Análise concluída com sucesso!");
            println!("📄 Relatório salvo em: {:?}", config.output_file);
            
            // 5. Exibe informações sobre o relatório gerado
            if let Ok(content) = std::fs::read_to_string(&config.output_file) {
                let lines: Vec<&str> = content.lines().collect();
                println!("📊 Relatório gerado com {} linhas", lines.len());
                
                // Exibe algumas linhas do relatório
                println!("\n📋 Preview do relatório:");
                for (i, line) in lines.iter().take(10).enumerate() {
                    println!("{:2}: {}", i + 1, line);
                }
                if lines.len() > 10 {
                    println!("... (mais {} linhas)", lines.len() - 10);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Erro durante a análise: {}", e);
            return Err(e);
        }
    }
    
    println!("\n🎉 Exemplo concluído!");
    Ok(())
}
