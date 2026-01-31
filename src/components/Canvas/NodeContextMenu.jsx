const NodeContextMenu = ({ contextMenu, onSetRoot, onClose }) => {
    if (!contextMenu) return null;

    return (
        <div
            className="node-context-menu"
            style={{
                top: contextMenu.top || undefined,
                left: contextMenu.left || undefined,
                right: contextMenu.right || undefined,
                bottom: contextMenu.bottom || undefined,
            }}
        >
            <p className="px-3 py-1 text-text-secondary text-xs border-b border-border-default truncate">
                {contextMenu.name}
            </p>
            <button onClick={() => { onSetRoot(contextMenu.id); onClose(); }}>
                Set as root
            </button>
        </div>
    );
};

export default NodeContextMenu;
