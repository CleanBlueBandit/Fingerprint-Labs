import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'node:fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const resourcesDir = path.join(__dirname, 'resources');

export function sendPublic(_path){
    return path.join(__dirname, "images/public", _path)
}

export function sendPrivate(_path){
    return path.join(__dirname, "images/authenticated", _path)
}

export function fileExists(file) {
    try {
        return fs.statSync(file).isFile();
    } catch {
        return false;
    }
}

