import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { authenticate } from './middleware.js';

const router = express.Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const resourcesDir = path.join(__dirname, '..', 'resources');

router.use(express.static(path.join(resourcesDir, 'public'), {
    dotfiles: 'ignore',
    index: false
}));

router.use(authenticate, express.static(path.join(resourcesDir, 'private'), {
    dotfiles: 'ignore',
    index: false
}));

router.use((req, res) => res.sendStatus(404));

export default router;