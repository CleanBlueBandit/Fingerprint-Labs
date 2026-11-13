-- CreateTable
CREATE TABLE "User" (
    "id" SERIAL NOT NULL,
    "username" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BrowserFingerprint" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "data" JSONB NOT NULL,
    "combinedHash" VARCHAR(64),
    "staticHash" VARCHAR(64),
    "configurationHash" VARCHAR(64),
    "behavioralHash" VARCHAR(64),
    "schemaVersion" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BrowserFingerprint_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_username_key" ON "User"("username");

-- CreateIndex
CREATE INDEX "BrowserFingerprint_userId_createdAt_idx" ON "BrowserFingerprint"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "BrowserFingerprint_combinedHash_idx" ON "BrowserFingerprint"("combinedHash");

-- CreateIndex
CREATE INDEX "BrowserFingerprint_staticHash_idx" ON "BrowserFingerprint"("staticHash");

-- CreateIndex
CREATE INDEX "BrowserFingerprint_configurationHash_idx" ON "BrowserFingerprint"("configurationHash");

-- CreateIndex
CREATE INDEX "BrowserFingerprint_behavioralHash_idx" ON "BrowserFingerprint"("behavioralHash");

-- AddForeignKey
ALTER TABLE "BrowserFingerprint" ADD CONSTRAINT "BrowserFingerprint_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
