import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Production serves the built dashboard under /dashboard (see
// scripts/deploy.sh Nginx config), while local dev still runs on its
// own port at the root. `base` only affects the production build.
export default defineConfig(({ command }) => ({
  plugins: [react(), tailwindcss()],
  base: command === 'build' ? '/dashboard/' : '/',
  server: {
    port: 3000,
    proxy: {
      '/api': 'http://localhost:8400',
      '/ws': {
        target: 'ws://localhost:8400',
        ws: true,
      },
    },
  },
}))
