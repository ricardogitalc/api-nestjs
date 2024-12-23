/*
  Warnings:

  - You are about to drop the column `anddress` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "anddress",
ADD COLUMN     "address" TEXT;
