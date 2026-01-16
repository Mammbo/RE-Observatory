import { create } from 'zustand';

export const useCFGNodeStore = create((set) => ({
    activePanel: null,
    panelWidth: 320, 
    minPanelWidth: 100, 
    maxPanelWidth: 750, 
    isResizing: false,
    // DATA STATE
    panels: {},


    registerPanel: (address, data) => 
        set((state) => ({
            panels: {
                ...state.panels,
                [address]: {
                    meta: {},
                    content: {},
                    graphs: {},
                    ...(state.panels[address] ?? {}),
                    ...data,
                }
            }
        })),
    
    togglePanel: (address) => set((state) => ({activePanel: state.activePanel === address ? null : address})), 
    setPanelWidth: (width) => set((state) => { 
        if (width >= state.minPanelWidth && width <= state.maxPanelWidth) {
            return { panelWidth: width }
        }
        return state;
    }),
    setIsResizing: (bool) => set(() => ({isResizing: bool}))
}));

export default useCFGNodeStore;