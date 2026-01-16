import useSideBarStore from '../../store/sideBarStore';

const ResizableHandle = () => {    
    const { panelWidth, minPanelWidth, maxPanelWidth, setPanelWidth } = useSideBarStore();
    const handleMouseDown = (e) => {
        e.preventDefault();
        const x = e.clientX;
        const initialWidth = panelWidth;

            const mouseMoveHandler = (e) => { 
                const dx = e.clientX - x; // Resize from left to right
                const newWidth = initialWidth + dx;

                if (newWidth >= minPanelWidth && newWidth <= maxPanelWidth) {
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
            className="w-1 h-full cursor-col-resize bg-border-default hover:bg-border-hover transition-colors"
        />
    );
}

export default ResizableHandle