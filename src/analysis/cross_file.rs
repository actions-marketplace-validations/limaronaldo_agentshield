//! Cross-file sanitizer-aware validation tracking.
//!
//! Runs after parsing, before detection. When a function is only ever called
//! with sanitized arguments, downgrades its parameters' `ArgumentSource` from
//! tainted to `Sanitized`. This eliminates false positives from internal
//! helper functions that receive already-validated input from their callers.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::ir::ArgumentSource;
use crate::parser::ParsedFile;

/// Known sanitizer function names and their categories.
static SANITIZER_NAMES: &[&str] = &[
    // Path sanitizers
    "validatePath",
    "sanitizePath",
    "normalizePath",
    "resolvePath",
    "canonicalizePath",
    "realpath",
    // Node.js path module (method part after dot)
    "resolve",
    "normalize",
    // Python path functions
    "abspath",
    "normpath",
    // URL sanitizers
    "parseUrl",
    "urlparse",
    // Type coercion
    "parseInt",
    "parseFloat",
    "Number",
    "int",
    "float",
    "str",
];

/// Check if a function name (or the method part of `obj.method`) is a sanitizer.
pub fn is_sanitizer(name: &str) -> bool {
    // Check exact match
    if SANITIZER_NAMES.contains(&name) {
        return true;
    }
    // Check method part: "path.resolve" → "resolve"
    if let Some(method) = name.rsplit('.').next() {
        if SANITIZER_NAMES.contains(&method) {
            return true;
        }
    }
    // Check common patterns
    let lower = name.to_lowercase();
    lower.contains("validate") && (lower.contains("path") || lower.contains("url"))
}

/// Result of cross-file sanitization analysis.
#[derive(Debug)]
pub struct CrossFileResult {
    /// Number of operations whose ArgumentSource was downgraded.
    pub downgraded_count: usize,
    /// Functions determined to receive only sanitized input.
    pub sanitized_functions: Vec<String>,
}

/// Perform cross-file sanitizer-aware analysis on parsed files.
///
/// For each function definition, checks if ALL discovered call sites pass
/// sanitized (or literal) arguments for each parameter. If so, downgrades
/// the function's operations from tainted to `Sanitized`.
///
/// Conservative: exported functions with zero discovered call sites keep
/// their parameters tainted.
pub fn apply_cross_file_sanitization(
    parsed_files: &mut [(PathBuf, ParsedFile)],
) -> CrossFileResult {
    let mut downgraded_count = 0;
    let mut sanitized_functions = Vec::new();

    // Phase 1: Build function definition map.
    // Key: function name → (file index, param names)
    let mut func_defs: HashMap<String, Vec<(usize, Vec<String>, bool)>> = HashMap::new();
    for (idx, (_, parsed)) in parsed_files.iter().enumerate() {
        for def in &parsed.function_defs {
            func_defs.entry(def.name.clone()).or_default().push((
                idx,
                def.params.clone(),
                def.is_exported,
            ));
        }
    }

    // Phase 2: Build call-site map.
    // Key: callee name → Vec of (argument sources)
    let mut call_sites: HashMap<String, Vec<Vec<ArgumentSource>>> = HashMap::new();
    for (_, parsed) in parsed_files.iter() {
        for cs in &parsed.call_sites {
            call_sites
                .entry(cs.callee.clone())
                .or_default()
                .push(cs.arguments.clone());
        }
    }

    // Phase 3: Determine which functions have all-sanitized parameters.
    // For each function with a definition AND call sites, check if every
    // call site passes safe (Literal or Sanitized) values for each param.
    let mut params_to_downgrade: Vec<(usize, String, String)> = Vec::new(); // (file_idx, param_name, sanitizer)

    for (func_name, defs) in &func_defs {
        let sites = match call_sites.get(func_name) {
            Some(s) if !s.is_empty() => s,
            _ => {
                // No discovered call sites. If exported, stay conservative.
                continue;
            }
        };

        for (file_idx, params, _is_exported) in defs {
            // Check each parameter position
            for (param_idx, param_name) in params.iter().enumerate() {
                let all_safe = sites.iter().all(|args| {
                    args.get(param_idx)
                        .map(|arg| !arg.is_tainted())
                        .unwrap_or(false) // Missing arg = can't prove safe
                });

                if all_safe {
                    params_to_downgrade.push((*file_idx, param_name.clone(), func_name.clone()));
                }
            }
        }
    }

    // Phase 4: Downgrade operations in the target functions.
    for (file_idx, param_name, func_name) in &params_to_downgrade {
        let (_, parsed) = &mut parsed_files[*file_idx];
        let sanitizer_label = format!("caller passes sanitized value to {func_name}");

        let sanitized = ArgumentSource::Sanitized {
            sanitizer: sanitizer_label.clone(),
        };

        // Downgrade matching ArgumentSource::Parameter in all operation types
        for cmd in &mut parsed.commands {
            if matches!(&cmd.command_arg, ArgumentSource::Parameter { name } if name == param_name)
            {
                cmd.command_arg = sanitized.clone();
                downgraded_count += 1;
            }
        }
        for op in &mut parsed.file_operations {
            if matches!(&op.path_arg, ArgumentSource::Parameter { name } if name == param_name) {
                op.path_arg = sanitized.clone();
                downgraded_count += 1;
            }
        }
        for op in &mut parsed.network_operations {
            if matches!(&op.url_arg, ArgumentSource::Parameter { name } if name == param_name) {
                op.url_arg = sanitized.clone();
                downgraded_count += 1;
            }
        }
        for op in &mut parsed.dynamic_exec {
            if matches!(&op.code_arg, ArgumentSource::Parameter { name } if name == param_name) {
                op.code_arg = sanitized.clone();
                downgraded_count += 1;
            }
        }

        if !sanitized_functions.contains(func_name) {
            sanitized_functions.push(func_name.clone());
        }
    }

    CrossFileResult {
        downgraded_count,
        sanitized_functions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::execution_surface::{FileOpType, FileOperation};
    use crate::ir::SourceLocation;
    use crate::parser::{CallSite, FunctionDef};

    fn loc(file: &str, line: usize) -> SourceLocation {
        SourceLocation {
            file: PathBuf::from(file),
            line,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    #[test]
    fn sanitizer_names_recognized() {
        assert!(is_sanitizer("validatePath"));
        assert!(is_sanitizer("path.resolve"));
        assert!(is_sanitizer("os.path.realpath"));
        assert!(is_sanitizer("parseInt"));
        assert!(is_sanitizer("urlparse"));
        assert!(!is_sanitizer("processData"));
        assert!(!is_sanitizer("readFile"));
    }

    #[test]
    fn custom_validate_path_recognized() {
        assert!(is_sanitizer("validate_path"));
        assert!(is_sanitizer("validateUrl"));
    }

    #[test]
    fn cross_file_downgrade() {
        // File A (index.ts): calls readFileContent with sanitized arg
        let mut file_a = ParsedFile::default();
        file_a.call_sites.push(CallSite {
            callee: "readFileContent".into(),
            arguments: vec![ArgumentSource::Sanitized {
                sanitizer: "validatePath".into(),
            }],
            caller: Some("handleRead".into()),
            location: loc("index.ts", 5),
        });

        // File B (lib.ts): defines readFileContent, uses filePath param
        let mut file_b = ParsedFile::default();
        file_b.function_defs.push(FunctionDef {
            name: "readFileContent".into(),
            params: vec!["filePath".into()],
            is_exported: true,
            location: loc("lib.ts", 1),
        });
        file_b.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter {
                name: "filePath".into(),
            },
            operation: FileOpType::Read,
            location: loc("lib.ts", 3),
        });

        let mut files = vec![
            (PathBuf::from("index.ts"), file_a),
            (PathBuf::from("lib.ts"), file_b),
        ];

        let result = apply_cross_file_sanitization(&mut files);

        assert_eq!(result.downgraded_count, 1);
        assert_eq!(result.sanitized_functions, vec!["readFileContent"]);

        // Verify the operation was downgraded
        let lib_ops = &files[1].1.file_operations;
        assert!(!lib_ops[0].path_arg.is_tainted());
        assert!(matches!(
            &lib_ops[0].path_arg,
            ArgumentSource::Sanitized { .. }
        ));
    }

    #[test]
    fn no_downgrade_when_unsanitized_caller_exists() {
        // Two call sites: one safe, one tainted
        let mut file_a = ParsedFile::default();
        file_a.call_sites.push(CallSite {
            callee: "readFile".into(),
            arguments: vec![ArgumentSource::Sanitized {
                sanitizer: "validatePath".into(),
            }],
            caller: Some("safeHandler".into()),
            location: loc("safe.ts", 5),
        });
        file_a.call_sites.push(CallSite {
            callee: "readFile".into(),
            arguments: vec![ArgumentSource::Parameter {
                name: "userInput".into(),
            }],
            caller: Some("unsafeHandler".into()),
            location: loc("safe.ts", 10),
        });

        let mut file_b = ParsedFile::default();
        file_b.function_defs.push(FunctionDef {
            name: "readFile".into(),
            params: vec!["path".into()],
            is_exported: true,
            location: loc("lib.ts", 1),
        });
        file_b.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter {
                name: "path".into(),
            },
            operation: FileOpType::Read,
            location: loc("lib.ts", 3),
        });

        let mut files = vec![
            (PathBuf::from("safe.ts"), file_a),
            (PathBuf::from("lib.ts"), file_b),
        ];

        let result = apply_cross_file_sanitization(&mut files);

        assert_eq!(result.downgraded_count, 0);
        // Operation stays tainted
        assert!(files[1].1.file_operations[0].path_arg.is_tainted());
    }

    #[test]
    fn no_downgrade_for_exported_with_no_callers() {
        let mut file_a = ParsedFile::default();
        file_a.function_defs.push(FunctionDef {
            name: "dangerousFunc".into(),
            params: vec!["input".into()],
            is_exported: true,
            location: loc("lib.ts", 1),
        });
        file_a.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter {
                name: "input".into(),
            },
            operation: FileOpType::Write,
            location: loc("lib.ts", 3),
        });

        let mut files = vec![(PathBuf::from("lib.ts"), file_a)];

        let result = apply_cross_file_sanitization(&mut files);

        assert_eq!(result.downgraded_count, 0);
        assert!(files[0].1.file_operations[0].path_arg.is_tainted());
    }

    #[test]
    fn downgrade_only_matching_params() {
        // Function with 2 params, only first is always sanitized
        let mut file_a = ParsedFile::default();
        file_a.call_sites.push(CallSite {
            callee: "copyFile".into(),
            arguments: vec![
                ArgumentSource::Sanitized {
                    sanitizer: "validatePath".into(),
                },
                ArgumentSource::Parameter {
                    name: "rawDest".into(),
                },
            ],
            caller: Some("handler".into()),
            location: loc("index.ts", 5),
        });

        let mut file_b = ParsedFile::default();
        file_b.function_defs.push(FunctionDef {
            name: "copyFile".into(),
            params: vec!["src".into(), "dest".into()],
            is_exported: true,
            location: loc("lib.ts", 1),
        });
        // Two file operations, one per param
        file_b.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter { name: "src".into() },
            operation: FileOpType::Read,
            location: loc("lib.ts", 3),
        });
        file_b.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter {
                name: "dest".into(),
            },
            operation: FileOpType::Write,
            location: loc("lib.ts", 4),
        });

        let mut files = vec![
            (PathBuf::from("index.ts"), file_a),
            (PathBuf::from("lib.ts"), file_b),
        ];

        let result = apply_cross_file_sanitization(&mut files);

        assert_eq!(result.downgraded_count, 1); // Only src
        assert!(!files[1].1.file_operations[0].path_arg.is_tainted()); // src: safe
        assert!(files[1].1.file_operations[1].path_arg.is_tainted()); // dest: still tainted
    }
}
