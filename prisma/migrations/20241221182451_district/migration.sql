/*
  Warnings:

  - You are about to drop the column `neighborhood` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "neighborhood",
ADD COLUMN     "district" TEXT;
