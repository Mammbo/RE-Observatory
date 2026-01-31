// use the call graph data to create nodes

const renderNodes = (callGraph) => {
    return Object.entries(callGraph.nodes).map(([addr, info]) => ({
        id: addr,
        type: 'CFG',
        data: { src: addr, name: info.name, type: info.type },
        deletable: false,
    }));
}

export default renderNodes;
