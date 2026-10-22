import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { initializeAnalytics } from './analytics';
import App from './App';
import './styles.css';

if (import.meta.env.PROD) initializeAnalytics(import.meta.env.VITE_GA_MEASUREMENT_ID);

createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
