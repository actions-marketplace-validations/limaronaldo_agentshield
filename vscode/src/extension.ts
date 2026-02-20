import * as vscode from "vscode";
import { runScan } from "./scanner";
import { updateDiagnostics } from "./diagnostics";

let scanTimer: ReturnType<typeof setTimeout> | undefined;
let isScanning = false;

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection("agentshield");
  const output = vscode.window.createOutputChannel("AgentShield");
  const statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBar.command = "agentshield.scan";
  statusBar.show();

  context.subscriptions.push(diagnostics, output, statusBar);

  // Command: manual scan
  context.subscriptions.push(
    vscode.commands.registerCommand("agentshield.scan", () =>
      scan(diagnostics, output, statusBar)
    )
  );

  // Auto-scan on save (debounced)
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(() => {
      const config = vscode.workspace.getConfiguration("agentshield");
      if (!config.get<boolean>("scanOnSave", true)) {
        return;
      }
      if (scanTimer) {
        clearTimeout(scanTimer);
      }
      scanTimer = setTimeout(() => scan(diagnostics, output, statusBar), 2000);
    })
  );

  // Scan on workspace open
  const config = vscode.workspace.getConfiguration("agentshield");
  if (config.get<boolean>("scanOnOpen", true)) {
    scan(diagnostics, output, statusBar);
  }
}

async function scan(
  diagnostics: vscode.DiagnosticCollection,
  output: vscode.OutputChannel,
  statusBar: vscode.StatusBarItem
): Promise<void> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    return;
  }

  if (isScanning) {
    return;
  }
  isScanning = true;

  const workspacePath = workspaceFolders[0].uri.fsPath;

  statusBar.text = "$(sync~spin) AgentShield...";
  statusBar.tooltip = "Scanning for security issues...";

  try {
    const report = await runScan(workspacePath, output);

    if (!report) {
      statusBar.text = "$(error) AgentShield";
      statusBar.tooltip = "Scan failed — check Output panel";
      diagnostics.clear();
      return;
    }

    updateDiagnostics(report, diagnostics, workspacePath);

    const count = report.verdict.effective_findings;
    if (count === 0) {
      statusBar.text = "$(check) AgentShield";
      statusBar.tooltip = "No security findings";
      statusBar.color = undefined;
    } else {
      statusBar.text = `$(warning) AgentShield: ${count} finding${count !== 1 ? "s" : ""}`;
      statusBar.tooltip = `${count} security finding${count !== 1 ? "s" : ""} — click to rescan`;
      statusBar.color = new vscode.ThemeColor(
        report.verdict.pass
          ? "statusBarItem.warningForeground"
          : "statusBarItem.errorForeground"
      );
    }

    output.appendLine(
      `Scan complete: ${count} finding(s), verdict: ${report.verdict.pass ? "PASS" : "FAIL"}`
    );
  } finally {
    isScanning = false;
  }
}

export function deactivate(): void {
  if (scanTimer) {
    clearTimeout(scanTimer);
  }
}
