// Public handler — validates path before passing to helper.
// This is the pattern used by the Anthropic filesystem MCP server.
import { validatePath } from "./utils";
import { readFileContent, writeFileContent, listDirectory } from "./operations";

export async function handleReadFile(args: { path: string }) {
    const validPath = await validatePath(args.path);
    const content = await readFileContent(validPath);
    return { content };
}

export async function handleWriteFile(args: { path: string; content: string }) {
    const validPath = await validatePath(args.path);
    await writeFileContent(validPath, args.content);
    return { success: true };
}

export async function handleListDirectory(args: { path: string }) {
    const validPath = await validatePath(args.path);
    const entries = await listDirectory(validPath);
    return { entries };
}
