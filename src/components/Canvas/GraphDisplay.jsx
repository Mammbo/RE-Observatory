import { ReactFlow, ReactFlowProvider, Background, Controls, applyEdgeChanges, applyNodeChanges, addEdge, SelectionMode, MiniMap, ConnectionLineType, Panel } from '@xyflow/react';
import { useState, useCallback, useEffect } from 'react';
import '@xyflow/react/dist/style.css';
import NoteNode from './NoteNode';
import CFGNode from './CFGNode';
import AddNodeButton from './AddNoteButton';
import renderEdges from './edges';
import renderNodes from './nodes';
import useAnalysisStore from '../../store/analysisStore';
import ELK from 'elkjs/lib/elk.bundled.js'


// initalize ELKGraph 
const elk = new ELK();

// CFGNode dimensions: w-50 = 200px, h-25 = 100px
const nodeWidth = 160;
const nodeHeight = 80;

// layout of dagreGraph
const getLayoutedElements = async (nodes, edges, direction = 'DOWN') => {
    const elkGraph = { 
        id: 'root',
        layoutOptions: {
            'elk.algorithm': 'layered',
            // Space between nodes on the same level (like nodesep in dagre)                                           
            'elk.spacing.nodeNode': '30',                                                                              
            // Space between levels/layers (like ranksep in dagre)                                                     
            'elk.layered.spacing.nodeNodeBetweenLayers': '50',  
            //direction for elk 
            'elk.direction': direction,    
            'elk.layer.crossingMinimization.strategy': 'LAYER_SWEEP',
            'elk.layered.spacing.edgeNodeBetweenLayers': '20',
            'elk.spacing.edgeNode': '20',
            'elk.spacing.edgeEdge': '15',
            'elk.layered.edgeRouting': 'ORTHOGONAL'                               
        },
        children: nodes.map((node) => ({
            id: node.id, 
            width: nodeWidth,
            height: nodeHeight,
        })),
        edges: edges.map((edge) => ({
            id: edge.id,
            sources: [edge.source],
            targets: [edge.target],
        })),
    }

    const layoutedGraph = await elk.layout(elkGraph);

    const layoutedNodes = nodes.map((node) => { 
        const elkNode = layoutedGraph.children.find((n) => n.id === node.id);
        return { 
            ...node,
            position : { x: elkNode.x, y: elkNode.y},
            targetPosition: direction === 'RIGHT' ? 'left' : 'top',                                                    
            sourcePosition: direction === 'RIGHT' ? 'right' : 'bottom',   
        };
    });

    return { nodes: layoutedNodes, edges };
};


const nodeTypes = {
        note: NoteNode,
        CFG: CFGNode
    }

const CanvasView = () => {
    const { isLoading, analysisData } = useAnalysisStore();
    const [nodes, setNodes] = useState([]);
    const [edges, setEdges] = useState([]);

    // When analysis is done and call graph exists, render and layout
    useEffect(() => {
        if (!isLoading && analysisData?.callGraph) {
            const rawNodes = renderNodes(analysisData.callGraph);
            const rawEdges = renderEdges(analysisData.callGraph);

            // Count connections per node
            const connectionCount = {};
            rawEdges.forEach((edge) => {
                connectionCount[edge.source] = (connectionCount[edge.source] || 0) + 1;
                connectionCount[edge.target] = (connectionCount[edge.target] || 0) + 1;
            });

            // Find threshold for "major" nodes (top 10% by connections)
            const counts = Object.values(connectionCount);
            const sortedCounts = [...counts].sort((a, b) => b - a);
            const majorThreshold = sortedCounts[Math.floor(sortedCounts.length * 0.1)] || 1;

            // Find entry node: LIEF address → named entry/main/_start → most connected
            const liefEntry = analysisData?.programInfo?.meta?.entrypoint;
            const entryNodeId =
                rawNodes.find(n => n.id === liefEntry)?.id
                || rawNodes.find(n => n.data.name === 'entry')?.id
                || rawNodes.find(n => n.data.name === 'main')?.id
                || rawNodes.find(n => n.data.name === '_start')?.id
                || Object.entries(connectionCount).sort((a, b) => b[1] - a[1])[0]?.[0]
                || rawNodes[0]?.id;

            // Enrich nodes with highlight info
            const enrichedNodes = rawNodes.map((node) => ({
                ...node,
                data: {
                    ...node.data,
                    isEntry: node.id === entryNodeId,
                    isMajor: (connectionCount[node.id] || 0) >= majorThreshold,
                    connectionCount: connectionCount[node.id] || 0,
                },
            }));

            const layoutGraph = async () => { 
                const { nodes: layoutedNodes, edges: layoutedEdges } = 
                await getLayoutedElements(enrichedNodes, rawEdges);
            setNodes(layoutedNodes);
            setEdges(layoutedEdges);
            }
            layoutGraph();
        }
    }, [isLoading, analysisData]);
    // on Node Changes 
    const onNodesChange = useCallback(
        (changes) => setNodes((nodesSnapshot) => applyNodeChanges(changes, nodesSnapshot)),
        [],
    );
    const onEdgesChange = useCallback(
        (changes) => setEdges((edgesSnapshot) => applyEdgeChanges(changes, edgesSnapshot)),
        [],
    );
    const onConnect = useCallback(
        (params) => setEdges((edgesSnapshot) => addEdge(params, edgesSnapshot)),
        [],
    );
    const onLayout = useCallback(
        async (direction) => {
            const { nodes: layoutedNodes, edges: layoutedEdges } =  await getLayoutedElements(nodes, edges, direction);
            setNodes([...layoutedNodes]);
            setEdges([...layoutedEdges]);
        },
        [nodes, edges],
    );
    return (
            <div className='w-full h-full relative'>
                {/* Title fixed to viewport center, never shifts */}
                <div className="fixed top-4 left-1/2 -translate-x-1/2 z-5 pointer-events-none">
                    <h1 className="text-2xl font-bold tracking-wide text-accent drop-shadow-lg">
                        Reverse Engineering Observatory
                    </h1>
                </div>
                <ReactFlowProvider>
                    <ReactFlow
                        nodes={nodes}
                        edges={edges}
                        nodeTypes={nodeTypes}
                        onNodesChange={onNodesChange}
                        onEdgesChange={onEdgesChange}
                        onConnect={onConnect}
                        connectionLineType={ConnectionLineType.SimpleBezier}
                        defaultEdgeOptions={{ type: 'simplebezier' }}
                        selectionMode={SelectionMode.Partial}
                        colorMode='dark'
                        minZoom={0.1}
                        fitView
                        >
                        <Panel position="top-right" className="flex gap-2">
                            <button className="px-3 py-1 bg-elevated text-text-primary rounded hover:bg-active text-sm" onClick={() => onLayout('DOWN')}>
                            Vertical
                            </button>
                            <button className="px-3 py-1 bg-elevated text-text-primary rounded hover:bg-active text-sm" onClick={() => onLayout('RIGHT')}>
                            Horizontal
                            </button>
                        </Panel>
                        <MiniMap nodeStrokeWidth={3} zoomable pannable />
                        <Background />
                        <Controls>
                            <AddNodeButton />    
                        </Controls>    
                    </ReactFlow>
                </ReactFlowProvider>
            </div>
    );
};

export default CanvasView;