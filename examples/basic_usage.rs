use codeql_chatgpt_analyzer::prelude::*;

/// Basic usage example of the CodeQL ChatGPT Analyzer library
#[tokio::main]
async fn main() -> Result<()> {
    // Setup logging
    tracing_subscriber::fmt::init();
    
    println!("🚀 Basic usage example of CodeQL ChatGPT Analyzer");
    
    // 1. Load configuration from environment
    let config = match Config::from_env() {
        Ok(config) => {
            println!("✅ Configuration loaded successfully");
            config
        }
        Err(e) => {
            eprintln!("❌ Error loading configuration: {}", e);
            eprintln!("💡 Configure the required environment variables");
            return Err(e);
        }
    };
    
    // 2. Validate configuration
    if let Err(e) = config.validate() {
        eprintln!("❌ Invalid configuration: {}", e);
        return Err(e);
    }
    
    println!("📁 Project: {:?}", config.project_root);
    println!("🤖 Model: {}", config.model);
    println!("📄 Output: {:?}", config.output_file);
    
    // 3. Create analyzer
    let analyzer = match CodeQLAnalyzer::new(config.clone()) {
        Ok(analyzer) => {
            println!("✅ Analyzer created successfully");
            analyzer
        }
        Err(e) => {
            eprintln!("❌ Error creating analyzer: {}", e);
            return Err(e);
        }
    };
    
    // 4. Execute analysis
    println!("🔍 Starting analysis...");
    
    match analyzer.analyze("examples/sample-codeql-results.json").await {
        Ok(()) => {
            println!("✅ Analysis completed successfully!");
            println!("📄 Report saved to: {:?}", config.output_file);
            
            // 5. Display information about the generated report
            if let Ok(content) = std::fs::read_to_string(&config.output_file) {
                let lines: Vec<&str> = content.lines().collect();
                println!("📊 Report generated with {} lines", lines.len());
                
                // Display some lines from the report
                println!("\n📋 Report preview:");
                for (i, line) in lines.iter().take(10).enumerate() {
                    println!("{:2}: {}", i + 1, line);
                }
                if lines.len() > 10 {
                    println!("... ({} more lines)", lines.len() - 10);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Error during analysis: {}", e);
            return Err(e);
        }
    }
    
    println!("\n🎉 Example completed!");
    Ok(())
}
