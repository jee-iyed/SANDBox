import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// SANDBox frontend. Port 3000 (8000 is reserved for IOC-Hunter).
// host '0.0.0.0' so the dev server is reachable from Docker containers.
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    strictPort: true,
  },
  preview: {
    host: '0.0.0.0',
    port: 3000,
    strictPort: true,
  },
});