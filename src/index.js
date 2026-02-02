import React from 'react';
import ReactDOM from 'react-dom/client';
import './styles/index.css';
import App from './App.jsx';
import { ToastProvider } from './components/Layout/Toast';

// Suppress benign ResizeObserver loop error (common with React Flow)
const resizeObserverErrHandler = (e) => {
  if (e.message?.includes?.('ResizeObserver loop') ||
      e.error?.message?.includes?.('ResizeObserver loop')) {
    e.stopImmediatePropagation();
    e.preventDefault();
    return;
  }
};
window.addEventListener('error', resizeObserverErrHandler);
window.addEventListener('unhandledrejection', resizeObserverErrHandler);

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <ToastProvider>
      <App />
    </ToastProvider>
  </React.StrictMode>
);