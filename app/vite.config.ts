import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';

const certDir = path.resolve(__dirname, 'cert');
const hasCerts = fs.existsSync(path.join(certDir, 'signet.pem'));

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    host: '0.0.0.0',
    https: hasCerts
      ? {
          cert: fs.readFileSync(path.join(certDir, 'signet.pem')),
          key: fs.readFileSync(path.join(certDir, 'signet-key.pem')),
        }
      : undefined,
  },
  resolve: {
    alias: {
      'signet-protocol': path.resolve(__dirname, '../src'),
      'canary-kit': path.resolve(__dirname, '../../canary-kit/src'),
    },
  },
});
