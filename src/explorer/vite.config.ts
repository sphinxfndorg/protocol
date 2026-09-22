import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        // import.meta.dirname is the ESM equivalent of __dirname; Vite 8's
        // native config loader warns on __dirname and plans to remove support.
        '@': path.resolve(import.meta.dirname),
      },
    },
    server: {
      port: 3000,
      host: '0.0.0.0',
      // Proxy API requests to the Go backend node. Without this the Vite dev
      // server answers /api/* itself with index.html, every explorerApi fetch
      // fails to parse as JSON, and the UI silently renders the simulated mock
      // chain instead of real chain data.
      //
      // Must match the node's --http-port (default 8545). Change the target if
      // the node was started on another port (e.g. 8546 for a second validator).
      proxy: {
        '/api': {
          target: 'http://localhost:8545',
          changeOrigin: true,
          secure: false,
        },
      },
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modifyâfile watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
