/*
  Warnings:

  - You are about to drop the column `whatsapp` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "whatsapp",
ADD COLUMN     "phone" TEXT;
