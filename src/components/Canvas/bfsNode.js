// Builds outgoing adjacency list from edge array
const buildAdjacency = (edges) => {
    const adjacency = {};
    edges.forEach((edge) => {
        if (!adjacency[edge.source]) adjacency[edge.source] = [];
        adjacency[edge.source].push(edge.target);
    });
    return adjacency;
};

// BFS from root following outgoing edges, returns Set of node IDs within maxDepth
export const bfsFromRoot = (rootId, edges, maxDepth) => {
    const adjacency = buildAdjacency(edges);

    const visited = new Set();
    const queue = [{ id: rootId, depth: 0 }];
    visited.add(rootId);

    while (queue.length > 0) {
        const { id, depth } = queue.shift();
        if (depth >= maxDepth) continue;

        const neighbors = adjacency[id] || [];
        for (const neighbor of neighbors) {
            if (!visited.has(neighbor)) {
                visited.add(neighbor);
                queue.push({ id: neighbor, depth: depth + 1 });
            }
        }
    }

    return visited;
};

// BFS with no depth limit — returns the max depth reachable from rootId
export const getMaxDepth = (rootId, edges) => {
    const adjacency = buildAdjacency(edges);

    const visited = new Set();
    const queue = [{ id: rootId, depth: 0 }];
    visited.add(rootId);
    let maxDepth = 0;

    while (queue.length > 0) {
        const { id, depth } = queue.shift();
        if (depth > maxDepth) maxDepth = depth;

        const neighbors = adjacency[id] || [];
        for (const neighbor of neighbors) {
            if (!visited.has(neighbor)) {
                visited.add(neighbor);
                queue.push({ id: neighbor, depth: depth + 1 });
            }
        }
    }

    return maxDepth;
};
