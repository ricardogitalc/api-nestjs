export interface ApiResponse {
  result: 'success' | 'error';
  statusCode: number;
  data?: any;
  timestamp: string;
  path: string;
}
