import { create } from 'zustand';

const useAnalysisStore = create((set) => ({
    analysisData: null,
    isLoading: false,
    error: null,
    dbReady: false,
    binaryId: null,

    setAnalysisData: (data) => set({ analysisData: data }),
    setIsLoading: (loading) => set({ isLoading: loading }),
    setError: (error) => set({ error: error }),
    setDbReady: (ready) => set({ dbReady: ready }),
    setBinaryId: (id) => set({ binaryId: id }),

    // Computed getters for convenience
    getProgramInfo: () => {
        const state = useAnalysisStore.getState();
        return state.analysisData?.programInfo?.meta || null;
    },

    getSecurityFeatures: () => {
        const state = useAnalysisStore.getState();
        return state.analysisData?.programInfo?.meta?.security || null;
    },

    getDecompiled: (address) => {
        const state = useAnalysisStore.getState();
        return state.analysisData?.decompiled?.[address] || null;
    },

    getCFG: (address) => {
        const state = useAnalysisStore.getState();
        return state.analysisData?.cfgs?.[address] || null;
    },
}));

export default useAnalysisStore;
