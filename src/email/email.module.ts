import { Module } from '@nestjs/common';
import { ResendService } from './resend-client';

@Module({
  providers: [ResendService],
  exports: [ResendService],
})
export class EmailModule {}
