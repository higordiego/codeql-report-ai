//! Utilitários para operações de arquivo e processamento

use crate::types::*;
use sha2::{Digest, Sha256};
use std::path::Path;
use walkdir::WalkDir;

/// Calcula o hash SHA256 de uma string
pub fn calculate_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Lê um arquivo de forma segura, limitando o tamanho
pub fn read_file_safe(path: &Path, max_bytes: usize) -> crate::Result<String> {
    let content = std::fs::read_to_string(path).map_err(crate::Error::Io)?;

    if content.len() > max_bytes {
        return Err(crate::Error::Config(format!(
            "Arquivo {} muito grande ({} bytes > {} bytes)",
            path.display(),
            content.len(),
            max_bytes
        )));
    }

    Ok(content)
}

/// Encontra arquivos Python no diretório especificado
pub fn find_python_files(root_dir: &Path) -> crate::Result<Vec<std::path::PathBuf>> {
    let mut python_files = Vec::new();

    tracing::debug!("Procurando arquivos Python em: {}", root_dir.display());

    // Diretórios que devem ser ignorados (não processar)
    let ignored_dirs = [
        "venv",
        "env",
        ".venv",
        ".env",
        "node_modules",
        ".node_modules",
        ".git",
        ".svn",
        ".hg",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".coverage",
        "build",
        "dist",
        "target",
        ".idea",
        ".vscode",
        ".vs",
        "logs",
        "tmp",
        "temp",
        ".DS_Store",
        "Thumbs.db",
        "site-packages",
        "lib",
        "lib64",
        "include",
        "bin",
        "share",
        "pip",
        "setuptools",
        "wheel",
        "pydantic",
        "requests",
        "urllib3",
        "certifi",
        "charset_normalizer",
        "idna",
        "six",
        "packaging",
        "pyparsing",
        "markupsafe",
        "jinja2",
        "click",
        "itsdangerous",
        "werkzeug",
        "flask",
        "django",
        "fastapi",
        "uvicorn",
        "starlette",
        "pydantic",
        "typing_extensions",
        "annotated_types",
        "python-dateutil",
        "pytz",
        "babel",
        "markdown",
        "pygments",
        "docutils",
        "sphinx",
        "alabaster",
        "imagesize",
        "snowballstemmer",
        "babel",
        "pytz",
        "six",
        "docutils",
        "markupsafe",
        "jinja2",
        "pygments",
        "alabaster",
        "imagesize",
        "snowballstemmer",
    ];

    for entry in WalkDir::new(root_dir)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        // Verifica se o caminho contém qualquer diretório ignorado
        let path_str = path.to_string_lossy().to_lowercase();
        let contains_ignored = ignored_dirs.iter().any(|&ignored| {
            path_str.contains(&format!("/{}/", ignored))
                || path_str.contains(&format!("\\{}\\", ignored))
                || path_str.ends_with(&format!("/{}", ignored))
                || path_str.ends_with(&format!("\\{}", ignored))
                || path_str.contains(&format!("{}/", ignored))
                || path_str.contains(&format!("{}\\", ignored))
        });

        if contains_ignored {
            tracing::debug!(
                "Ignorando caminho que contém diretório ignorado: {}",
                path.display()
            );
            continue;
        }

        // Se é um diretório ignorado, pula completamente
        if path.is_dir() {
            if let Some(dir_name) = path.file_name() {
                let dir_name_str = dir_name.to_string_lossy().to_lowercase();
                if ignored_dirs.iter().any(|&ignored| dir_name_str == ignored) {
                    tracing::debug!("Ignorando diretório completamente: {}", path.display());
                    continue;
                }
            }
        }

        // Se é um arquivo, verifica se é Python
        if path.is_file() {
            if let Some(extension) = path.extension() {
                if extension == "py" {
                    tracing::debug!("Arquivo Python encontrado: {}", path.display());
                    python_files.push(path.to_path_buf());
                }
            }
        }
    }

    tracing::debug!(
        "Total de arquivos Python encontrados: {}",
        python_files.len()
    );
    Ok(python_files)
}

/// Calcula a prioridade de um arquivo baseado em seu caminho
pub fn calculate_file_priority(path: &Path) -> i32 {
    let path_str = path.to_string_lossy().to_lowercase();
    let mut score = 0;

    // Arquivos principais têm alta prioridade
    if path_str.contains("main.py") || path_str.contains("app.py") {
        score += 50;
    }

    if path_str.contains("__init__.py") {
        score += 30;
    }

    // Arquivos de configuração têm prioridade média
    if path_str.contains("config") || path_str.contains("settings") {
        score += 20;
    }

    // Arquivos de modelo têm prioridade alta
    if path_str.contains("models") || path_str.contains("views") || path_str.contains("controllers")
    {
        score += 40;
    }

    if path_str.contains("tests/") || path_str.contains("test_") {
        score -= 20; // Testes têm menor prioridade
    }

    score
}

/// Divide arquivos em chunks baseado no tamanho alvo
pub fn create_chunks(
    files: Vec<std::path::PathBuf>,
    target_tokens: usize,
) -> crate::Result<Vec<Chunk>> {
    let mut chunks = Vec::new();
    let mut chunk_id = 0;

    for file_path in files {
        let content = read_file_safe(&file_path, 350000)?;
        let estimated_tokens = content.len() / 4; // Estimativa aproximada

        // Se o arquivo é muito grande, divide em múltiplos chunks
        if estimated_tokens > target_tokens {
            let lines: Vec<&str> = content.lines().collect();
            let mut current_line = 0;

            while current_line < lines.len() {
                let end_line = std::cmp::min(current_line + target_tokens / 4, lines.len());
                let chunk_content = lines[current_line..end_line].join("\n");
                let content_len = chunk_content.len();

                let chunk = Chunk::new(
                    format!("chunk_{}", chunk_id),
                    file_path.clone(),
                    chunk_content,
                    current_line + 1,
                    end_line,
                    content_len / 4,
                );

                chunks.push(chunk);
                chunk_id += 1;
                current_line = end_line;
            }
        } else {
            // Arquivo cabe em um chunk
            let line_count = content.lines().count();
            let chunk = Chunk::new(
                format!("chunk_{}", chunk_id),
                file_path.clone(),
                content,
                1,
                line_count,
                estimated_tokens,
            );

            chunks.push(chunk);
            chunk_id += 1;
        }
    }

    Ok(chunks)
}

/// Cria chunks apenas com as linhas específicas reportadas pelo CodeQL
pub fn create_targeted_chunks(
    files: Vec<std::path::PathBuf>,
    codeql_results: &[CodeQLResult],
    context_lines: usize,
) -> crate::Result<Vec<Chunk>> {
    let mut chunks = Vec::new();
    let mut chunk_id = 0;

    // Agrupa resultados por arquivo
    let mut file_results: std::collections::HashMap<String, Vec<&CodeQLResult>> =
        std::collections::HashMap::new();

    for result in codeql_results {
        file_results
            .entry(result.file_path.clone())
            .or_default()
            .push(result);
    }

    for file_path in files {
        let file_str = file_path.to_string_lossy();

        // Extrai apenas o nome do arquivo para comparação
        let file_name = file_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown");

        // Debug: mostra os caminhos sendo comparados
        tracing::debug!(
            "Comparando arquivo encontrado: '{}' (nome: '{}')",
            file_str,
            file_name
        );
        for sarif_path in file_results.keys() {
            tracing::debug!("  com caminho SARIF: '{}'", sarif_path);
        }

        // Verifica se há resultados para este arquivo (compara por nome do arquivo)
        let results = file_results
            .iter()
            .find(|(sarif_path, _)| {
                // Extrai o nome do arquivo do caminho SARIF
                let sarif_file_name = std::path::Path::new(sarif_path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");

                tracing::debug!("  Comparando '{}' com '{}'", file_name, sarif_file_name);
                file_name == sarif_file_name
            })
            .map(|(_, results)| results.clone());

        if let Some(results) = results {
            // Lê o arquivo
            let content = read_file_safe(&file_path, 350000)?;
            let lines: Vec<&str> = content.lines().collect();

            // Debug: mostra o conteúdo do arquivo
            tracing::debug!(
                "Conteúdo do arquivo {} ({} linhas):",
                file_path.display(),
                lines.len()
            );
            for (i, line) in lines.iter().enumerate() {
                tracing::debug!("  Linha {}: {}", i + 1, line);
            }

            // Coleta todas as linhas que precisam ser incluídas
            let mut target_lines = std::collections::HashSet::new();

            for result in results {
                if let Some(line_num) = result.line_number {
                    let line_idx = (line_num as usize) - 1; // Converte para índice baseado em 0

                    // Adiciona a linha do problema
                    target_lines.insert(line_idx);

                    // Adiciona linhas de contexto (antes e depois)
                    let start_context = line_idx.saturating_sub(context_lines);
                    let end_context = std::cmp::min(line_idx + context_lines + 1, lines.len());

                    for i in start_context..end_context {
                        target_lines.insert(i);
                    }
                }
            }

            // Converte para lista ordenada
            let mut sorted_lines: Vec<usize> = target_lines.into_iter().collect();
            sorted_lines.sort();

            // Cria chunks com as linhas específicas
            if !sorted_lines.is_empty() {
                let mut current_chunk_lines = Vec::new();
                let chunk_start_line = sorted_lines[0] + 1;
                let mut chunk_end_line = sorted_lines[0] + 1;

                for &line_idx in &sorted_lines {
                    if line_idx < lines.len() {
                        current_chunk_lines.push(lines[line_idx]);
                        chunk_end_line = line_idx + 1;
                    }
                }

                let chunk_content = current_chunk_lines.join("\n");
                let estimated_tokens = chunk_content.len() / 4;

                let chunk = Chunk::new(
                    format!("targeted_chunk_{}", chunk_id),
                    file_path.clone(),
                    chunk_content,
                    chunk_start_line,
                    chunk_end_line,
                    estimated_tokens,
                );

                chunks.push(chunk);
                chunk_id += 1;
            }
        }
    }

    Ok(chunks)
}
