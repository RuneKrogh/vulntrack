import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { ReportPage } from './report.tsx'

// The public report form has its own address, so it can be linked to from outside.
createRoot(document.getElementById('root')!).render(
  <StrictMode>{window.location.pathname === '/report' ? <ReportPage /> : <App />}</StrictMode>,
)
