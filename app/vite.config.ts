import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';
import http from 'http';

const certDir = path.resolve(__dirname, 'cert');
const hasCerts = fs.existsSync(path.join(certDir, 'signet.pem'));

/** Start a tiny HTTP server that redirects all requests to the HTTPS port. */
function httpsRedirect(httpsPort: number, httpPort: number): Plugin {
  return {
    name: 'https-redirect',
    configureServer() {
      if (!hasCerts) return;
      const server = http.createServer((req, res) => {
        const host = (req.headers.host || 'localhost').replace(/:\d+$/, '');
        res.writeHead(301, { Location: `https://${host}:${httpsPort}${req.url}` });
        res.end();
      });
      server.listen(httpPort, '0.0.0.0');
      console.log(`  ➜  HTTP redirect: http://localhost:${httpPort}/ → https://localhost:${httpsPort}/`);
    },
  };
}

export default defineConfig({
  plugins: [react(), httpsRedirect(5174, 5180)],
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
    },
  },
});
