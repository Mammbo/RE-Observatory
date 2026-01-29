import { useCFGNodeStore } from '../../store/cfgNodeStore';

const NodePanelResizeHandle = () => {
    const { panelWidth, minPanelWidth, maxPanelWidth, setPanelWidth, setIsResizing } = useCFGNodeStore();

    const handleMouseDown = (e) => {
        e.preventDefault();
        setIsResizing(true);
        const x = e.clientX;
        const initialWidth = panelWidth;

        const mouseMoveHandler = (e) => {
            // Resize from right to left (panel is on right side)
            const dx = x - e.clientX;
            const newWidth = initialWidth + dx;

            if (newWidth >= minPanelWidth && newWidth <= maxPanelWidth) {
                setPanelWidth(newWidth);
            }
        };

        const mouseUpHandler = () => {
            setIsResizing(false);
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
};

export default NodePanelResizeHandle;
