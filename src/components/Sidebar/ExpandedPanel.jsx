import { useEffect, useState } from "react";
import ResizableHandle from "./ResizeHandle";

const ExpandedPanel = ({activePanel, width, children}) => {
    const [shouldRender, setShouldRender] = useState(false);
    const [isVisible, setIsVisible] = useState(false);

    useEffect(() => {
        let timer;
        let rafId;
        if (activePanel) {
            setShouldRender(true);
            // Double RAF ensures browser has painted the initial state
            rafId = requestAnimationFrame(() => {
                rafId = requestAnimationFrame(() => {
                    setIsVisible(true);
                });
            });
        } else {
            setIsVisible(false);
            // Wait for exit animation to complete before unmounting
            timer = setTimeout(() => setShouldRender(false), 300);
        }
        return () => {
            clearTimeout(timer);
            cancelAnimationFrame(rafId);
        };
    }, [activePanel])
    if (!shouldRender) return null;
    return (
        <div className={`fixed top-0 left-16 h-screen bg-primary flex
                          origin-left transition-transform duration-300 ease-in-out
                          ${isVisible
                              ? 'scale-x-100'
                              : 'scale-x-0'
                          }`}
            style={{width}}>
            <div className="flex-1 overflow-auto">
                {children}
            </div>
            <ResizableHandle />
        </div>
    );
};

export default ExpandedPanel;