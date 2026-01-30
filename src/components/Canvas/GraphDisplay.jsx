import { ReactFlow, ReactFlowProvider, Background, Controls, applyEdgeChanges, applyNodeChanges, addEdge, SelectionMode, MiniMap, ConnectionLineType, Panel } from '@xyflow/react';
import { useState, useCallback, useEffect } from 'react';
import '@xyflow/react/dist/style.css';
import NoteNode from './NoteNode';
import CFGNode from './CFGNode';
import AddNodeButton from './AddNoteButton';
import renderEdges from './edges';
import renderNodes from './nodes';
import useAnalysisStore from '../../store/analysisStore';
import dagre from 'dagre'

// initalize dagreGraph 
const dagreGraph = new dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}));

// CFGNode dimensions: w-50 = 200px, h-25 = 100px
const nodeWidth = 200;
const nodeHeight = 100;

// layout of dagreGraph
const getLayoutedElements = (nodes, edges, direction = 'TB') => {
    const isHorizontal = direction === 'LR';
    dagreGraph.setGraph({ rankdir: direction });

    nodes.forEach((node) => {
        dagreGraph.setNode(node.id, { width: nodeWidth, height: nodeHeight });
    });

    edges.forEach((edge) => {
        dagreGraph.setEdge(edge.source, edge.target);
    });

    dagre.layout(dagreGraph);

    const newNodes = nodes.map((node) => {
        const nodeWithPosition = dagreGraph.node(node.id);
        const newNode = {
            ...node,
            targetPosition: isHorizontal ? 'left' : 'top',
            sourcePosition: isHorizontal ? 'right' : 'bottom',
            position: {
                x: nodeWithPosition.x - nodeWidth / 2,
                y: nodeWithPosition.y - nodeHeight / 2,
            },
        };
        return newNode;
    });
    return { nodes: newNodes, edges };
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

            // Get entrypoint address
            const entrypoint = analysisData?.programInfo?.meta?.entrypoint;

            // Enrich nodes with highlight info
            const enrichedNodes = rawNodes.map((node) => ({
                ...node,
                data: {
                    ...node.data,
                    isEntry: node.id === entrypoint,
                    isMajor: (connectionCount[node.id] || 0) >= majorThreshold,
                    connectionCount: connectionCount[node.id] || 0,
                },
            }));

            const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(enrichedNodes, rawEdges);
            setNodes(layoutedNodes);
            setEdges(layoutedEdges);
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
        (direction) => {
            const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(nodes, edges, direction);
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
                        connectionLineType={ConnectionLineType.SmoothStep}
                        defaultEdgeOptions={{ type: 'smoothstep' }}
                        selectionMode={SelectionMode.Partial}
                        colorMode='dark'
                        minZoom={0.1}
                        fitView
                        >
                        <Panel position="top-right" className="flex gap-2">
                            <button className="px-3 py-1 bg-elevated text-text-primary rounded hover:bg-active text-sm" onClick={() => onLayout('TB')}>
                            Vertical
                            </button>
                            <button className="px-3 py-1 bg-elevated text-text-primary rounded hover:bg-active text-sm" onClick={() => onLayout('LR')}>
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