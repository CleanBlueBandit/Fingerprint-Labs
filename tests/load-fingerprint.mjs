// Loads the browser scripts into one Node vm context so their pure parts can be tested
// without a browser. Anything that needs a real DOM, GPU or audio device is NOT covered.
import vm from 'node:vm';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'resources', 'private');

export function loadFingerprint(files, extraGlobals = {}) {
    const sandbox = {
        console, TextEncoder, TextDecoder, URL, setTimeout, clearTimeout,
        crypto: webcrypto,
        navigator: {},
        performance,
        ...extraGlobals
    };
    sandbox.window = sandbox;
    const context = vm.createContext(sandbox);
    for (const file of files) {
        vm.runInContext(fs.readFileSync(path.join(root, file), 'utf8'), context, { filename: file });
    }
    // classic-script const/class declarations are not properties of the global object,
    // so expose what the tests need through one expression
    return {
        context,
        get: (expression) => vm.runInContext(expression, context)
    };
}
