import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// In development the backend runs on port 5000. Vite forwards the API and login routes
// to it, so the browser sees a single origin just like in production.
const backend = 'http://localhost:5000'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': backend,
      '/auth': backend,
      '/signin-oidc': backend,
      '/signout-callback-oidc': backend,
    },
  },
})
