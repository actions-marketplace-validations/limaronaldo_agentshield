use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, RuleMetadata, Severity,
};

/// SHIELD-007: Prompt Injection Surface
///
/// Flags tools that fetch external content (HTTP, file read) and could
/// return it unsanitized to the LLM. External content may contain
/// adversarial instructions that hijack the agent's behavior.
pub struct PromptInjectionDetector;

impl Detector for PromptInjectionDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-007".into(),
            name: "Prompt Injection Surface".into(),
            description:
                "Tool fetches external content that may be returned unsanitized to the LLM".into(),
            default_severity: Severity::Medium,
            attack_category: AttackCategory::PromptInjectionSurface,
            cwe_id: None,
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Any network GET that reads external content is a prompt injection surface
        for net_op in &target.execution.network_operations {
            // Only flag reads (GET), not sends (POST with sends_data)
            if net_op.sends_data {
                continue;
            }

            findings.push(Finding {
                rule_id: "SHIELD-007".into(),
                rule_name: "Prompt Injection Surface".into(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                attack_category: AttackCategory::PromptInjectionSurface,
                message: format!(
                    "'{}' fetches external content that may be returned to the LLM unsanitized",
                    net_op.function
                ),
                location: Some(net_op.location.clone()),
                evidence: vec![Evidence {
                    description: format!("External content fetch via '{}'", net_op.function),
                    location: Some(net_op.location.clone()),
                    snippet: None,
                }],
                taint_path: None,
                remediation: Some(
                    "Sanitize or escape external content before returning it to the LLM. \
                     Consider stripping HTML tags, limiting response length, and adding \
                     content boundaries."
                        .into(),
                ),
                cwe_id: None,
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::execution_surface::*;
    use crate::ir::*;
    use std::path::PathBuf;

    fn loc() -> SourceLocation {
        SourceLocation {
            file: PathBuf::from("server.py"),
            line: 10,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    #[test]
    fn flags_get_request() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                network_operations: vec![NetworkOperation {
                    function: "requests.get".into(),
                    url_arg: ArgumentSource::Parameter { name: "url".into() },
                    method: Some("GET".into()),
                    sends_data: false,
                    location: loc(),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };
        let findings = PromptInjectionDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-007");
    }

    #[test]
    fn ignores_post_with_data() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                network_operations: vec![NetworkOperation {
                    function: "requests.post".into(),
                    url_arg: ArgumentSource::Literal("https://api.example.com".into()),
                    method: Some("POST".into()),
                    sends_data: true,
                    location: loc(),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };
        let findings = PromptInjectionDetector.run(&target);
        assert!(findings.is_empty());
    }
}
