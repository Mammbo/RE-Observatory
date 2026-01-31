const DepthSlider = ({ depthLimit, maxDepthValue, onDepthChange, onReset }) => {
    return (
        <div className="flex items-center gap-2 bg-elevated rounded px-3 py-1">
            <span className="text-text-primary text-sm whitespace-nowrap">
                Depth: {depthLimit}
            </span>
            <input
                type="range"
                min={1}
                max={maxDepthValue || 1}
                value={depthLimit ?? maxDepthValue}
                onChange={(e) => onDepthChange(Number(e.target.value))}
                className="w-28 accent-accent"
            />
            <button
                className="px-2 py-0.5 bg-active text-text-secondary rounded hover:text-text-primary text-xs"
                onClick={onReset}
            >
                Reset
            </button>
        </div>
    );
};

export default DepthSlider;
