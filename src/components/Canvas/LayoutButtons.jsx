const LayoutButtons = ({ onLayout }) => {
    return (
        <div className="flex gap-2 justify-end">
            <button
                className="px-3 py-1 bg-elevated text-text-primary rounded hover:bg-active text-sm"
                onClick={() => onLayout('DOWN')}
            >
                Vertical
            </button>
            <button
                className="px-3 py-1 bg-elevated text-text-primary rounded hover:bg-active text-sm"
                onClick={() => onLayout('RIGHT')}
            >
                Horizontal
            </button>
        </div>
    );
};

export default LayoutButtons;
