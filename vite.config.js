import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(), 
  ],
  server: {
    watch: {
      // ข้ามการจับตาดูไฟล์ที่เปลี่ยนแปลงในโฟลเดอร์ backend (ป้องกันหน้าเว็บ reload เอง)
      ignored: ['**/backend/**'],
    },
  },
})