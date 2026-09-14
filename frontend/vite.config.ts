import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const backendPort = Number(process.env.BACKEND_PORT || process.env.PORT || 8787);
const frontendPort = Number(process.env.FRONTEND_PORT || 5302);
const bindHost = process.env.BIND_HOST || '127.0.0.1';

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          const modulePath = id.replace(/\\/g, '/');

          if (
            modulePath.includes('/node_modules/react/') ||
            modulePath.includes('/node_modules/react-dom/') ||
            modulePath.includes('/node_modules/react-router/') ||
            modulePath.includes('/node_modules/react-router-dom/') ||
            modulePath.includes('/node_modules/@remix-run/router/') ||
            modulePath.includes('/node_modules/scheduler/')
          ) {
            return 'react-vendor';
          }

          if (
            modulePath.includes('/node_modules/echarts/') ||
            modulePath.includes('/node_modules/echarts-for-react/') ||
            modulePath.includes('/node_modules/zrender/')
          ) {
            return 'echarts-vendor';
          }

          if (modulePath.includes('/node_modules/animejs/')) {
            return 'animejs-vendor';
          }
        },
      },
    },
  },
  server: {
    host: bindHost,
    port: frontendPort,
    strictPort: true,
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${backendPort}`,
        // 大文件 multipart 上传：避免代理默认超时导致前端报 Network Error
        timeout: 30 * 60_000,
        proxyTimeout: 30 * 60_000,
      },
      '/ws': {
        target: `ws://127.0.0.1:${backendPort}`,
        ws: true,
      },
    },
  },
});
