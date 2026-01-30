// first initalize all nodes 
// initalize all edge connections


// tasks
// - add node collision detection 
// - add vertical and horizontal tree layout rendering with dagre
// - add ability to save tree w/ button to database 
// - add context menu  to note nodes to duplicate or delete them 
// - add highlighting key nodes and edges
// 

const renderEdges = (callGraph) => {
    return callGraph.edges.map((edge, index) => ({
        id: `e-${edge.src}-${edge.dst}-${index}`,
        source: edge.src,
        target: edge.dst,
    }));
}

export default renderEdges;