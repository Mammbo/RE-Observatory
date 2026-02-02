import { createContext, useContext, useState, useCallback } from 'react';

const ToastContext = createContext(null);

export const useToast = () => useContext(ToastContext);

const typeStyles = {
    error: 'bg-red-900/90 border-red-500 text-red-100',
    success: 'bg-green-900/90 border-green-500 text-green-100',
    info: 'bg-secondary border-accent text-text-primary',
};

const Toast = ({ toast, onDismiss }) => (
    <div
        className={`flex items-start gap-3 px-4 py-3 rounded-lg border shadow-lg backdrop-blur-sm max-w-sm
            animate-[slideIn_0.3s_ease-out] ${typeStyles[toast.type] || typeStyles.info}`}
    >
        <span className="text-sm flex-1 break-words">{toast.message}</span>
        <button
            onClick={() => onDismiss(toast.id)}
            className="text-current opacity-60 hover:opacity-100 text-lg leading-none shrink-0"
        >
            &times;
        </button>
    </div>
);

export const ToastProvider = ({ children }) => {
    const [toasts, setToasts] = useState([]);

    const showToast = useCallback((message, type = 'info') => {
        const id = Date.now() + Math.random();
        setToasts((prev) => [...prev, { id, message, type }]);
        setTimeout(() => {
            setToasts((prev) => prev.filter((t) => t.id !== id));
        }, 5000);
    }, []);

    const dismiss = useCallback((id) => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
    }, []);

    return (
        <ToastContext.Provider value={{ showToast }}>
            {children}
            <div className="fixed bottom-4 right-4 z-[200] flex flex-col gap-2 pointer-events-auto">
                {toasts.map((t) => (
                    <Toast key={t.id} toast={t} onDismiss={dismiss} />
                ))}
            </div>
        </ToastContext.Provider>
    );
};
