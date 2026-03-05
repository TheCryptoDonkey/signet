import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import fs from 'fs';

const certDir = path.resolve(__dirname, '../app/cert');
const hasCerts = fs.existsSync(path.join(certDir, 'signet.pem'));

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      'signet-protocol': path.resolve(__dirname, '../src'),
    },
  },
  server: {
    port: 5175,
    host: '0.0.0.0',
    ...(hasCerts
      ? {
          https: {
            cert: fs.readFileSync(path.join(certDir, 'signet.pem')),
            key: fs.readFileSync(path.join(certDir, 'signet-key.pem')),
          },
        }
      : {}),
  },
});
