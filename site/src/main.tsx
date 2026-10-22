import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { initializeAnalytics } from './analytics';
import App from './App';
import './styles.css';

initializeAnalytics();

createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
