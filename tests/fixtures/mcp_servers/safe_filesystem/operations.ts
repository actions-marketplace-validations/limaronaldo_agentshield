// Internal helpers — receive already-validated paths from handlers.
// These should NOT trigger SHIELD-004 or SHIELD-006 findings because
// cross-file analysis sees that all callers pass sanitized values.
import * as fs from "fs/promises";

export async function readFileContent(filePath: string): Promise<string> {
    return fs.readFile(filePath, "utf-8");
}

export async function writeFileContent(filePath: string, content: string): Promise<void> {
    await fs.writeFile(filePath, content, "utf-8");
}

export async function listDirectory(dirPath: string): Promise<string[]> {
    const entries = await fs.readdir(dirPath);
    return entries;
}
