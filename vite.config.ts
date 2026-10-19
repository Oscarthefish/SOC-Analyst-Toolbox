import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The frontend calls relative /api URLs; dev and preview servers forward them to the
// local backend. changeOrigin rewrites Host so it passes the backend's Host check.
const api = {
  '/api': {
    target: `http://127.0.0.1:${process.env.BACKEND_PORT ?? 8787}`,
    changeOrigin: true,
  },
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: api },
  preview: { proxy: api },
})
