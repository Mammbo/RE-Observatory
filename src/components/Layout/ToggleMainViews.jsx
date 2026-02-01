import { useState } from 'react';

const ToggleMainViews = ({ activeView, onToggle }) => {
    return (
        <div className="flex items-center gap-1 bg-secondary rounded-lg p-1 shadow-lg border border-border-default" style={{ WebkitAppRegion: 'no-drag' }}>
            <button
                onClick={() => onToggle('canvas')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all duration-200 cursor-pointer
                    ${activeView === 'canvas'
                        ? 'bg-accent text-text-inverse shadow-sm'
                        : 'text-text-secondary hover:text-text-primary hover:bg-hover'
                    }`}
            >
                Canvas
            </button>
            <button
                onClick={() => onToggle('terminal')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all duration-200 cursor-pointer
                    ${activeView === 'terminal'
                        ? 'bg-accent text-text-inverse shadow-sm'
                        : 'text-text-secondary hover:text-text-primary hover:bg-hover'
                    }`}
            >
                Terminal
            </button>
        </div>
    );
};

export default ToggleMainViews;
