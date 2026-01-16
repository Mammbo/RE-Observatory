import { useEffect, useState } from 'react';
import { useCFGNodeStore } from '../../store/cfgNodeStore';
import NodePanelResizeHandle from './NodePanelResizeHandle';

const NodePanel = () => {
    const { activePanel, panels, panelWidth, togglePanel } = useCFGNodeStore();
    const [shouldRender, setShouldRender] = useState(false);
    const [isVisible, setIsVisible] = useState(false);
    const [currentPanel, setCurrentPanel] = useState(null);
    const [currentData, setCurrentData] = useState(null);

    const hasActivePanel = activePanel && panels[activePanel];

    useEffect(() => {
        let timer;
        if (hasActivePanel) {
            setCurrentPanel(activePanel);
            setCurrentData(panels[activePanel]);
            setShouldRender(true);
            timer = setTimeout(() => setIsVisible(true), 10);
        } else {
            setIsVisible(false);
            timer = setTimeout(() => {
                setShouldRender(false);
                setCurrentPanel(null);
                setCurrentData(null);
            }, 300);
        }
        return () => clearTimeout(timer);
    }, [hasActivePanel, activePanel, panels]);

    if (!shouldRender || !currentData) return null;

    return (
        <div
            className={`fixed top-0 right-0 h-screen bg-primary flex z-50
                        origin-right transition-transform duration-300 ease-in-out
                        ${isVisible ? 'scale-x-100' : 'scale-x-0'}`}
            style={{ width: panelWidth }}
        >
            <NodePanelResizeHandle />
            <div className="flex-1 overflow-auto">
                <div className="node-panel-header">
                    <span className="node-panel-address">{currentPanel}</span>
                    <button className="node-panel-close" onClick={() => togglePanel(currentPanel)}>
                        ×
                    </button>
                </div>
                <div className="node-panel-content">
                    {Object.entries(currentData).map(([key, value]) => {
                        if (typeof value === 'object' && Object.keys(value).length === 0) {
                            return null;
                        }
                        const displayValue = typeof value === 'object'
                            ? JSON.stringify(value)
                            : String(value);

                        return (
                            <div key={key} className="node-panel-field">
                                <span className="node-panel-key">{key}</span>
                                <span className="node-panel-value">{displayValue}</span>
                            </div>
                        );
                    })}
                </div>
            </div>
        </div>
    );
};

export default NodePanel;
