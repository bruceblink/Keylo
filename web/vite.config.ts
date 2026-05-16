import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/setup/',
  server: {
    proxy: {
      '/setup/status': 'http://127.0.0.1:2345',
      '/setup/initialize': 'http://127.0.0.1:2345'
    }
  }
});
