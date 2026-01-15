//  1. Create Zustand store (src/store/sidebarStore.js)
//    - State: activePanel, panelWidth, isResizing
//    - Actions: togglePanel(), closePanel(), setPanelWidth()
//  2. Add CSS classes (src/styles/index.css)
//    - .panel-header, .panel-content, .resize-handle
//    - .panel-section, .panel-row, .panel-label, .panel-value

import { create } from 'zustand';

export const useSideBarStore = create((set) => ({ 
    activePanel: null | 'binary' | 'signals' | 'analysis',
    panelWidth: 320, 
    minPanelWidth: 240, 
    maxPanelWidth: 600, 
    isResizing: false,

    togglePanel: (panelName) => set(() => ({activePanel: panelName})), 
    closePanel: () => set(() => ({activePanel: null})), 
    setPanelWidth: (width) => set((state) => { 
        if (state >= state.minPanelWidth || state <= state.maxPanelWidth) {
            return { panelWidth: width }
        }
        return state;
    }),
    setIsResizing: (bool) => set(() => ({isResizing: bool}))
}));