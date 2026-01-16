import { useCFGNodeStore } from '../../store/cfgNodeStore';

const NodePanelResizeHandle = () => {
    const { panelWidth, minPanelWidth, maxPanelWidth, setPanelWidth } = useCFGNodeStore();

    const handleMouseDown = (e) => {
        e.preventDefault();
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
