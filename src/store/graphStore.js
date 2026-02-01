import { create } from 'zustand';

const useGraphStore = create((set, get) => ({
    // Raw graph data (before layout)
    enrichedNodes: [],
    rawEdges: [],

    // Display state (after layout)
    nodes: [],
    edges: [],

    // User-created content (note nodes and manually drawn edges)
    userNodes: [],
    userEdges: [],

    // Graph metadata
    entryNodeId: null,

    // Depth filter state
    depthLimit: null,
    maxDepthValue: 1,
    filterRoot: null,

    // Actions — raw graph
    setEnrichedNodes: (nodes) => set({ enrichedNodes: nodes }),
    setRawEdges: (edges) => set({ rawEdges: edges }),
    setEntryNodeId: (id) => set({ entryNodeId: id }),

    // Actions — layouted graph (accept value or updater function)
    setNodes: (nodesOrFn) => set((state) => {
        const newNodes = typeof nodesOrFn === 'function' ? nodesOrFn(state.nodes) : nodesOrFn;
        // Sync dragged positions back into userNodes
        const updatedUserNodes = state.userNodes.map((un) => {
            const current = newNodes.find((n) => n.id === un.id);
            return current ? { ...un, position: current.position } : un;
        });
        return { nodes: newNodes, userNodes: updatedUserNodes };
    }),
    setEdges: (edgesOrFn) => set((state) => ({
        edges: typeof edgesOrFn === 'function' ? edgesOrFn(state.edges) : edgesOrFn,
    })),
    // Simple setter — caller is responsible for including user nodes/edges if needed
    setLayoutedGraph: (nodes, edges) => set({ nodes, edges }),
    addUserNode: (node) => set((state) => ({
        userNodes: [...state.userNodes, node],
        nodes: [...state.nodes, node],
    })),
    addUserEdge: (edge) => set((state) => ({
        userEdges: [...state.userEdges, edge],
        edges: [...state.edges, edge],
    })),
    removeUserNode: (id) => set((state) => ({
        userNodes: state.userNodes.filter((n) => n.id !== id),
        nodes: state.nodes.filter((n) => n.id !== id),
        edges: state.edges.filter((e) => e.source !== id && e.target !== id),
        userEdges: state.userEdges.filter((e) => e.source !== id && e.target !== id),
    })),
    updateUserNodeData: (id, dataUpdate) => set((state) => {
        const update = (list) => list.map((n) =>
            n.id === id ? { ...n, data: { ...n.data, ...dataUpdate } } : n
        );
        return { userNodes: update(state.userNodes), nodes: update(state.nodes) };
    }),

    // Actions — depth filter
    setDepthLimit: (n) => set({ depthLimit: n }),
    setMaxDepthValue: (n) => set({ maxDepthValue: n }),
    setFilterRoot: (id) => set({ filterRoot: id }),

    // Convenience: reset depth filter to entry node with full depth
    resetDepthFilter: () => {
        const { entryNodeId } = get();
        set({ filterRoot: null });
        return entryNodeId;
    },

    // Getters
    getEnrichedNodes: () => get().enrichedNodes,
    getRawEdges: () => get().rawEdges,
    getEntryNodeId: () => get().entryNodeId,
    getNodeById: (id) => get().nodes.find((n) => n.id === id) || null,
    getNodeCount: () => get().nodes.length,
    getEdgeCount: () => get().edges.length,
}));

export default useGraphStore;
