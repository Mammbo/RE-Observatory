import { ReactFlow, ReactFlowProvider, Background, Controls, applyEdgeChanges, applyNodeChanges, addEdge, SelectionMode, MiniMap, ConnectionLineType, Panel } from '@xyflow/react';
import { useState, useCallback, useEffect, useRef } from 'react';
import '@xyflow/react/dist/style.css';
import NoteNode from './NoteNode';
import CFGNode from './CFGNode';
import AddNodeButton from './AddNoteButton';
import NodeContextMenu from './NodeContextMenu';
import LayoutButtons from './LayoutButtons';
import DepthSlider from './DepthSlider';
import renderEdges from './edges';
import renderNodes from './nodes';
import useAnalysisStore from '../../store/analysisStore';
import useGraphStore from '../../store/graphStore';
import { useCFGNodeStore } from '../../store/cfgNodeStore';
import { resolveCollisions } from './resolveCollisions';
import { bfsFromRoot, getMaxDepth } from './bfsNode';
import useHighlight from './useHighlight';
import ELK from 'elkjs/lib/elk.bundled.js'
import SaveGraphButton from '../Layout/SaveGraphButton';


// initalize ELKGraph 
const elk = new ELK();

// Node sizes
const NODE_WIDTH = 140;
const NODE_HEIGHT = 70;
const MAJOR_NODE_WIDTH = 180;
const MAJOR_NODE_HEIGHT = 90;
const ENTRY_NODE_WIDTH = 220;
const ENTRY_NODE_HEIGHT = 110;

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
            width: node.data?.nodeWidth ?? NODE_WIDTH,
            height: node.data?.nodeHeight ?? NODE_HEIGHT,
        })),
        edges: edges.map((edge) => ({
            id: edge.id,
            sources: [edge.source],
            targets: [edge.target],
        })),
    }

    const layoutedGraph = await elk.layout(elkGraph);

    const elkNodeMap = new Map();
    layoutedGraph.children.forEach((n) => elkNodeMap.set(n.id, n));

    const layoutedNodes = nodes.map((node) => {
        const elkNode = elkNodeMap.get(node.id);
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
    const nodes = useGraphStore((s) => s.nodes);
    const edges = useGraphStore((s) => s.edges);
    const depthLimit = useGraphStore((s) => s.depthLimit);
    const maxDepthValue = useGraphStore((s) => s.maxDepthValue);
    const filterRoot = useGraphStore((s) => s.filterRoot);
    const {
        setNodes, setEdges, setEnrichedNodes, setRawEdges,
        setEntryNodeId, setDepthLimit, setMaxDepthValue, setFilterRoot,
        setLayoutedGraph,
    } = useGraphStore();
    const depthLimitRef = useRef(null);
    const filterRootRef = useRef(null);
    const initialLayoutDone = useRef(false);

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

            setEntryNodeId(entryNodeId);

            // Enrich nodes with highlight info and sizing
            const enrichedNodes = rawNodes.map((node) => {
                const cc = connectionCount[node.id] || 0;
                const isEntry = node.id === entryNodeId;
                const isMajor = cc >= majorThreshold;

                const nodeW = isEntry ? ENTRY_NODE_WIDTH : isMajor ? MAJOR_NODE_WIDTH : NODE_WIDTH;
                const nodeH = isEntry ? ENTRY_NODE_HEIGHT : isMajor ? MAJOR_NODE_HEIGHT : NODE_HEIGHT;

                return {
                    ...node,
                    data: {
                        ...node.data,
                        isEntry,
                        isMajor,
                        connectionCount: cc,
                        nodeWidth: nodeW,
                        nodeHeight: nodeH,
                    },
                };
            });

            // Store enriched data for depth filtering later
            setEnrichedNodes(enrichedNodes);
            setRawEdges(rawEdges);

            // Register panels for all nodes so the side panel can open on double-click
            const { registerPanel } = useCFGNodeStore.getState();
            enrichedNodes.forEach((node) => {
                registerPanel(node.data.src, {
                    name: node.data.name,
                    type: node.data.type,
                    isEntry: node.data.isEntry,
                    isMajor: node.data.isMajor,
                    connectionCount: node.data.connectionCount,
                });
            });

            // Compute max depth from entry node
            const computedMaxDepth = getMaxDepth(entryNodeId, rawEdges);
            setMaxDepthValue(computedMaxDepth);
            // Use ref to skip the depth useEffect on initial load
            depthLimitRef.current = computedMaxDepth;
            setDepthLimit(computedMaxDepth);

            const layoutGraph = async () => {
                const { nodes: layoutedNodes, edges: layoutedEdges } =
                    await getLayoutedElements(enrichedNodes, rawEdges);
                const { userNodes, userEdges } = useGraphStore.getState();
                setLayoutedGraph([...layoutedNodes, ...userNodes], [...layoutedEdges, ...userEdges]);
            }
            layoutGraph();
        }
    }, [isLoading, analysisData]);

    // Re-layout when depthLimit or filterRoot changes
    useEffect(() => {
        const { enrichedNodes, rawEdges, entryNodeId } = useGraphStore.getState();
        if (depthLimit === null || enrichedNodes.length === 0) return;

        // Skip if this is the initial load — first useEffect already handled layout
        if (!initialLayoutDone.current) {
            initialLayoutDone.current = true;
            return;
        }

        // Skip cascading re-triggers from setDepthLimit inside this effect
        if (depthLimit === depthLimitRef.current && filterRoot === filterRootRef.current) return;
        depthLimitRef.current = depthLimit;
        filterRootRef.current = filterRoot;

        const rootId = filterRoot || entryNodeId;
        if (!rootId) return;

        // Recompute max depth from the current root first
        const newMax = getMaxDepth(rootId, rawEdges);
        setMaxDepthValue(newMax);

        // Clamp depthLimit to the new max so the slider and BFS stay in sync
        const effectiveDepth = Math.min(depthLimit, newMax);

        const isDefaultView = !filterRoot && effectiveDepth >= newMax;
        let filteredNodes, filteredEdges;

        if (isDefaultView) {
            // Show entire graph including disconnected nodes
            filteredNodes = enrichedNodes;
            filteredEdges = rawEdges;
        } else {
            const visibleIds = bfsFromRoot(rootId, rawEdges, effectiveDepth);
            filteredNodes = enrichedNodes.filter((n) => visibleIds.has(n.id));
            filteredEdges = rawEdges.filter(
                (e) => visibleIds.has(e.source) && visibleIds.has(e.target)
            );
        }

        // Update depthLimit if it exceeds the new max (won't re-trigger due to ref guard)
        if (depthLimit > newMax) {
            depthLimitRef.current = newMax;
            setDepthLimit(newMax);
        }

        // Include user-created note nodes and edges that connect to visible CFG nodes
        const { userNodes, userEdges } = useGraphStore.getState();
        const visibleCfgIds = new Set(filteredNodes.map((n) => n.id));
        const visibleNoteNodes = userNodes.filter((n) => {
            // Keep note if it has a user edge connecting to a visible CFG node
            return userEdges.some(
                (e) => (e.source === n.id && visibleCfgIds.has(e.target))
                    || (e.target === n.id && visibleCfgIds.has(e.source))
            );
        });
        const allNodes = [...filteredNodes, ...visibleNoteNodes];
        const allNodeIds = new Set(allNodes.map((n) => n.id));
        const visibleUserEdges = userEdges.filter(
            (e) => allNodeIds.has(e.source) && allNodeIds.has(e.target)
        );
        const allEdges = [...filteredEdges, ...visibleUserEdges];

        const layoutGraph = async () => {
            const { nodes: layoutedNodes, edges: layoutedEdges } =
                await getLayoutedElements(allNodes, allEdges);
            setLayoutedGraph(layoutedNodes, layoutedEdges);
        };
        layoutGraph();
    }, [depthLimit, filterRoot]);
    // on Node Changes 
    const onNodesChange = useCallback(
        (changes) => setNodes((nodesSnapshot) => applyNodeChanges(changes, nodesSnapshot)),
        [],
    );
    const onEdgesChange = useCallback(
        (changes) => setEdges((edgesSnapshot) => applyEdgeChanges(changes, edgesSnapshot)),
        [],
    );
    const addUserEdge = useGraphStore((s) => s.addUserEdge);
    const onConnect = useCallback(
        (params) => {
            const edge = { ...params, id: `user-e-${params.source}-${params.target}-${Date.now()}` };
            addUserEdge(edge);
        },
        [addUserEdge],
    );
    const [contextMenu, setContextMenu] = useState(null);
    const flowRef = useRef(null);
    const onNodeContextMenu = useCallback((event, node) => {
        event.preventDefault();
        const pane = flowRef.current.getBoundingClientRect();
        setContextMenu({
            id: node.id,
            name: node.data?.name || node.id,
            top: event.clientY < pane.height - 200 ? event.clientY : false,
            left: event.clientX < pane.width - 200 ? event.clientX : false,
            right: event.clientX >= pane.width - 200 ? pane.width - event.clientX : false,
            bottom: event.clientY >= pane.height - 200 ? pane.height - event.clientY : false,
        });
    }, []);
    const { displayNodes, displayEdges, onNodeClick, clearHighlight } = useHighlight(nodes, edges);

    const onPaneClick = useCallback(() => {
        setContextMenu(null);
        clearHighlight();
    }, [clearHighlight]);
    const onNodeDragStop = useCallback(() => {
        setNodes((nds) =>
            resolveCollisions(nds, {
                maxIterations: Infinity,
                overlapThreshold: 0.5,
                margin: 15,
            }),
        );
    }, [setNodes]);
    const onLayout = useCallback(
        async (direction) => {
            const { nodes: layoutedNodes, edges: layoutedEdges } = await getLayoutedElements(nodes, edges, direction);
            setLayoutedGraph([...layoutedNodes], [...layoutedEdges]);
            setNodes((nds) =>
                resolveCollisions(nds, {
                    maxIterations: Infinity,
                    overlapThreshold: 0.5,
                    margin: 15,
                }),
            );
        },
        [nodes, edges],
    );
    return (
            <div className='w-full h-90% relative'>
                {/* Title fixed to viewport center, never shifts */}
                <div className="fixed top-4 left-1/2 -translate-x-1/2 z-5 pointer-events-none">
                    <h1 className="text-2xl font-bold tracking-wide text-accent drop-shadow-lg">
                        Reverse Engineering Observatory
                    </h1>
                </div>
                <ReactFlowProvider>
                    <ReactFlow
                        ref={flowRef}
                        nodes={displayNodes}
                        edges={displayEdges}
                        nodeTypes={nodeTypes}
                        onNodesChange={onNodesChange}
                        onEdgesChange={onEdgesChange}
                        onConnect={onConnect}
                        onNodeDragStop={onNodeDragStop}
                        onNodeClick={onNodeClick}
                        onNodeContextMenu={onNodeContextMenu}
                        onPaneClick={onPaneClick}
                        connectionLineType={ConnectionLineType.SimpleBezier}
                        defaultEdgeOptions={{type: 'simplebezier' }}
                        selectionMode={SelectionMode.Partial}
                        colorMode='dark'
                        minZoom={0.1}
                        fitView
                        >
                        <Panel position="top-right" className="flex flex-col gap-2">
                            <LayoutButtons onLayout={onLayout} />
                            <DepthSlider
                                depthLimit={depthLimit}
                                maxDepthValue={maxDepthValue}
                                onDepthChange={setDepthLimit}
                                onReset={() => {
                                    const { entryNodeId, rawEdges } = useGraphStore.getState();
                                    setFilterRoot(null);
                                    const max = getMaxDepth(entryNodeId, rawEdges);
                                    setMaxDepthValue(max);
                                    setDepthLimit(max);
                                }}
                            />
                            <SaveGraphButton />
                        </Panel>
                        <MiniMap nodeStrokeWidth={3} zoomable pannable />
                        <Background />
                        <Controls>
                            <AddNodeButton />    
                        </Controls>    
                        <NodeContextMenu
                            contextMenu={contextMenu}
                            onSetRoot={setFilterRoot}
                            onClose={() => setContextMenu(null)}
                        />
                    </ReactFlow>
                </ReactFlowProvider>
            </div>
    );
};

export default CanvasView;