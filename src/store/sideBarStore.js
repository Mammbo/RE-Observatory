//  1. Create Zustand store (src/store/sidebarStore.js)
//    - State: activePanel, panelWidth, isResizing
//    - Actions: togglePanel(), closePanel(), setPanelWidth()
//  2. Add CSS classes (src/styles/index.css)
//    - .panel-header, .panel-content, .resize-handle
//    - .panel-section, .panel-row, .panel-label, .panel-value

import { create } from 'zustand';
import ExpandedPanel from '../components/Sidebar/ExpandedPanel';

export const useSideBarStore = create((set) => ({ 
    activePanel: null,
    panelWidth: 320, 
    minPanelWidth: 100, 
    maxPanelWidth: 1000, 
    isResizing: false,

    togglePanel: (panelName) => set((state) => ({activePanel: state.activePanel === panelName ? null : panelName})), 
    setPanelWidth: (width) => set((state) => { 
        if (width >= state.minPanelWidth && width <= state.maxPanelWidth) {
            return { panelWidth: width }
        }
        return state;
    }),
    setIsResizing: (bool) => set(() => ({isResizing: bool}))
}));

export default useSideBarStore