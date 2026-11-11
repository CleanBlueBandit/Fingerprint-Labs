import { Router } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { authenticate } from './middleware.js';
import { sendPublic, sendPrivate} from '../helpers.js';
import { errorStatusCode, respondWithStatusCode } from '../error/errorpage.js';

const router = Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


router.get("/", (req, res) => {
    res.sendFile(sendPublic("index.html"));
})

router.get('/dashboard', authenticate, (req, res) => {
    res.sendFile(sendPrivate("dashboard.html"));
});

router.get("/login", (req, res) => {
    res.sendFile(sendPublic("login.html"));
})

router.get("/register", (req, res) => {
    res.sendFile(sendPublic("register.html"));
})

router.get("/fingerprint", authenticate, (req, res) => {
    res.sendFile(sendPrivate("fingerprint.html"));
})

router.get("/coffee", (req, res) => {
    return respondWithStatusCode(418, res);
})


export default router;