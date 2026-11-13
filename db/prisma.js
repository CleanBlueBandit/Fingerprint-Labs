import 'dotenv/config';
import { PrismaClient } from '../generated/prisma-client.mjs';
import { PrismaPg } from '@prisma/adapter-pg';

const connectionString = process.env.DB_DATABASE_URL_POOLED;

if (!connectionString) {
    throw new Error('DB_DATABASE_URL_POOLED is not configured');
}

const adapter = new PrismaPg({
    connectionString
});

const prisma = new PrismaClient({
    adapter
});

export default prisma;