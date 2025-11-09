mod scanner;
mod yara;

use scanner::Scanner;
use clap::Parser;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about = "Simple CLI scanner for Minecraft mod JAR files", long_about = None)]
struct Args {
    /// Path to the JAR file to scan
    #[arg(value_name = "FILE")]
    file: PathBuf,
    
    /// Show detailed output
    #[arg(short, long)]
    verbose: bool,
    
    /// Output results as JSON
    #[arg(short, long)]
    json: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    
    // Проверяем, что файл существует
    if !args.file.exists() {
        eprintln!("❌ Error: File '{}' not found", args.file.display());
        std::process::exit(1);
    }
    
    if args.verbose {
        println!("🔍 Scanning: {}", args.file.display());
        println!("📦 Loading YARA rules...");
    }
    
    // Создаём сканер
    let mut scanner = match Scanner::new() {
        Ok(scanner) => scanner,
        Err(e) => {
            eprintln!("❌ Failed to initialize scanner: {}", e);
            std::process::exit(1);
        }
    };
    
    if args.verbose {
        println!("✓ YARA rules loaded successfully");
        println!("📄 Reading JAR file...");
    }
    
    // Читаем файл
    let jar_data = match fs::read(&args.file) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("❌ Failed to read file: {}", e);
            std::process::exit(1);
        }
    };
    
    if args.verbose {
        println!("✓ File read successfully ({} bytes)", jar_data.len());
        println!("🔎 Starting scan...\n");
    }
    
    // Сканируем
    let results = match scanner.scan_jar_in_memory(&jar_data) {
        Ok(results) => results,
        Err(e) => {
            eprintln!("❌ Scan failed: {}", e);
            std::process::exit(1);
        }
    };
    
    // Фильтруем результаты (убираем executables и deprecated)
    let filtered_results: std::collections::HashMap<_, _> = results.into_iter()
        .filter(|(cat, _)| cat != "executables" && cat != "deprecated")
        .collect();
    
    // Вычисляем вердикт
    let (verdict, severity, score) = calculate_verdict(&filtered_results);
    
    // Выводим результаты
    if args.json {
        // JSON формат
        let json_output = serde_json::json!({
            "file": args.file.to_string_lossy(),
            "verdict": verdict,
            "severity": severity,
            "score": score,
            "matches": filtered_results
        });
        println!("{}", serde_json::to_string_pretty(&json_output)?);
    } else {
        // Человекочитаемый формат
        println!("╔════════════════════════════════════════════════════════════╗");
        println!("║              SCAN RESULTS                                  ║");
        println!("╠════════════════════════════════════════════════════════════╣");
        println!("║ File:     {:<48} ║", args.file.file_name().unwrap().to_string_lossy());
        println!("║ Verdict:  {:<48} ║", format!("{} ({})", verdict, severity));
        println!("║ Score:    {:<48} ║", format!("{}/100", score));
        println!("╚════════════════════════════════════════════════════════════╝");
        println!();
        
        if filtered_results.is_empty() {
            println!("✅ No suspicious patterns detected");
        } else {
            let total_matches: usize = filtered_results.values().map(|v| v.len()).sum();
            println!("⚠️  Found {} suspicious pattern(s) in {} categor(ies)\n", total_matches, filtered_results.len());
            
            for (category, matches) in &filtered_results {
                println!("📂 Category: {}", category.to_uppercase());
                println!("   {} match(es)", matches.len());
                
                if args.verbose {
                    for m in matches {
                        let severity_icon = match m.severity {
                            0 => "ℹ️",
                            1 => "⚡",
                            2 => "⚠️",
                            3 => "🔴",
                            4 => "💀",
                            _ => "❓",
                        };
                        println!("   {} [{}] {}", severity_icon, m.rule_name, m.description);
                        println!("      File: {}", m.file);
                        println!("      Details: {}", m.details);
                        println!();
                    }
                } else {
                    for m in matches.iter().take(3) {
                        let severity_icon = match m.severity {
                            0 => "ℹ️",
                            1 => "⚡",
                            2 => "⚠️",
                            3 => "🔴",
                            4 => "💀",
                            _ => "❓",
                        };
                        println!("   {} {}", severity_icon, m.description);
                    }
                    if matches.len() > 3 {
                        println!("   ... and {} more (use -v for details)", matches.len() - 3);
                    }
                }
                println!();
            }
        }
        
        // Итоговая рекомендация
        match verdict.as_str() {
            "Malicious" => {
                println!("🚨 VERDICT: This mod is likely CHEAT!");
                println!("   Recommendation: BAN CHEATER.");
            }
            "Suspicious" => {
                println!("⚠️  VERDICT: This mod appears SUSPICIOUS");
                println!("   Recommendation: Recheck mod with recaf or bytecode viewer.");
            }
            "Undetected" => {
                println!("⚡ VERDICT: Some potentially risky patterns detected");
                println!("   Recommendation: Maybe it's cheat or maybe not.");
            }
            _ => {
                println!("✅ VERDICT: No significant cheats detected");
                println!("   Note: This doesn't guarantee the mod is 100% clean.");
            }
        }
    }
    
    Ok(())
}

fn calculate_verdict(results: &std::collections::HashMap<String, Vec<scanner::Match>>) -> (String, String, u8) {
    let mut score = 0.0;
    let mut n = 0;
    let mut critical = false;
    let mut suspicious = false;
    let mut auth_high = 0;
    let mut filepath_high = 0;
    let mut classload_high = 0;
    
    for (cat, matches) in results.iter() {
        for m in matches {
            n += 1;
            let cat_weight = match cat.as_str() {
                "hitbox" => if m.severity >= 4 { 1.0 } else { 0.5 },
                "crystal_optimizer" => 1.0,
                "obfuscation" => if m.severity >= 3 { 0.7 } else { 0.4 },
                "autoattack" => 1.0,
                "swapper" => 0.5,
                _ => 0.1,
            };
            
            let sev_weight = match m.severity {
                0 => 0.0,
                1 => 2.0,
                2 => 5.0,
                3 => 20.0,
                4 => 100.0,
                _ => 0.0,
            };
            
            let likely_fp = m.rule_name.to_lowercase().contains("test")
                || m.description.to_lowercase().contains("test")
                || m.rule_name.to_lowercase().contains("example");
            
            let fp_weight = if likely_fp { 0.1 } else { 1.0 };
            
            score += cat_weight * sev_weight * fp_weight;
            
            if ["obfuscation", "network", "reflection", "urls"].contains(&cat.as_str()) && m.severity >= 3 {
                suspicious = true;
            }
            
            if cat == "authentication" && m.severity >= 4 {
                auth_high += 1;
            }
            if cat == "file_paths" && m.severity >= 3 {
                filepath_high += 1;
            }
            if cat == "class_loading" && m.severity >= 3 {
                classload_high += 1;
            }
        }
    }
    
    if n > 10 {
        score *= 10.0 / n as f64;
    }
    
    if n == 0 {
        return ("Benign".to_string(), "None".to_string(), 0);
    }
    
    if (auth_high >= 2 && filepath_high >= 1) 
        || (auth_high >= 1 && filepath_high >= 2) 
        || (auth_high >= 1 && classload_high >= 1) 
        || (filepath_high >= 1 && classload_high >= 1) {
        score = score.max(90.0);
        critical = true;
    }
    
    let (verdict, severity, mapped_score) = if critical || score >= 90.0 {
        ("Malicious".to_string(), "High".to_string(), (score.round() as u8).max(90).min(100))
    } else if suspicious || score >= 60.0 {
        ("Suspicious".to_string(), "Medium".to_string(), (score.round() as u8).max(60).min(89))
    } else if score >= 20.0 {
        ("Undetected".to_string(), "Low".to_string(), (score.round() as u8).max(20).min(59))
    } else {
        ("Benign".to_string(), "None".to_string(), (score.round() as u8).min(19))
    };
    
    (verdict, severity, mapped_score)
}