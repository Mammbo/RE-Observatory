import React from 'react'
import { useSideBarStore } from '../../store/sideBarStore';

const ResizableHandle = () => { 
    const { panelWidth, minPanelWidth, maxPanelWidth, setPanelWidth } = useSideBarStore();
    
    
    const handleMouseDown = (e) => {
        e.preventDefault();
        const x = e.clientX;
        const sbWidth = window.getComputedStyle(panelRef.current).width;
        const initialWidth = panelWidth;

            const mouseMoveHandler = (e) => { 
                const dx = x - e.clientX; // Resize from left to right
                dx = e.clientX - x; // Resix=ze from right to left
                const newWidth = initialWidth + dx;

                if (newWidth >= minPanelWidth || newWidth <= maxPanelWidth) {
                    setPanelWidth(newWidth);
                }
            };

            const mouseUpHandler = () => { 
                document.removeEventListener('mouseup', mouseUpHandler);
                document.removeEventListener('mousemove', mouseMoveHandler);
            };

            document.addEventListener('mousemove', mouseMoveHandler);
            document.addEventListener('mouseup', mouseUpHandler);
    };
    return (
        <div
            onMouseDown={handleMouseDown}
            className="w-1 h-full cursor-col-resize bg-gray-700 hover:bg-blue-500 transition-colors"
        />
    );
}

export default ResizableHandle