// Path validation utility — this is a sanitizer function.
import * as path from "path";

const ALLOWED_DIRS = ["/home/user/documents", "/tmp/workspace"];

export async function validatePath(requestedPath: string): Promise<string> {
    const resolved = path.resolve(requestedPath);
    const isAllowed = ALLOWED_DIRS.some(dir => resolved.startsWith(dir));
    if (!isAllowed) {
        throw new Error(`Access denied: ${resolved} is outside allowed directories`);
    }
    return resolved;
}
