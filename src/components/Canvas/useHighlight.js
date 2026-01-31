import { useState, useCallback, useMemo } from 'react';
import { MarkerType } from '@xyflow/react';

const HIGHLIGHT_COLOR = '#cba6f7';

const useHighlight = (nodes, edges) => {
    const [highlightedNode, setHighlightedNode] = useState(null);

    const connectedSet = useMemo(() => {
        if (!highlightedNode) return null;
        const set = new Set([highlightedNode]);
        edges.forEach((e) => {
            if (e.source === highlightedNode) set.add(e.target);
            if (e.target === highlightedNode) set.add(e.source);
        });
        return set;
    }, [highlightedNode, edges]);

    const displayNodes = useMemo(() => {
        if (!connectedSet) return nodes;
        return nodes.map((node) => ({
            ...node,
            data: {
                ...node.data,
                isHighlighted: node.id === highlightedNode,
                isDimmed: !connectedSet.has(node.id),
            },
        }));
    }, [nodes, connectedSet, highlightedNode]);

    const displayEdges = useMemo(() => {
        if (!connectedSet) return edges;
        return edges.map((edge) => {
            const isConnected = edge.source === highlightedNode || edge.target === highlightedNode;
            if (isConnected) {
                return {
                    ...edge,
                    style: { stroke: HIGHLIGHT_COLOR, strokeWidth: 2 },
                    markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16, color: HIGHLIGHT_COLOR },
                };
            }
            return {
                ...edge,
                style: { opacity: 0.15 },
            };
        });
    }, [edges, connectedSet, highlightedNode]);

    const onNodeClick = useCallback((_, node) => {
        setHighlightedNode((prev) => prev === node.id ? null : node.id);
    }, []);

    const clearHighlight = useCallback(() => {
        setHighlightedNode(null);
    }, []);

    return { displayNodes, displayEdges, onNodeClick, clearHighlight };
};

export default useHighlight;
