import { useEffect, useState, useMemo } from 'react';
import { useCFGNodeStore } from '../../store/cfgNodeStore';
import useAnalysisStore from '../../store/analysisStore';
import NodePanelResizeHandle from './NodePanelResizeHandle';
import { Accordion, AccordionItem } from '@heroui/accordion';
import { ReactFlow, ReactFlowProvider, Background, Handle, Position } from '@xyflow/react';
import ELK from 'elkjs/lib/elk.bundled.js';
import '@xyflow/react/dist/style.css';

const elk = new ELK();

const EDGE_COLORS = {
    FALL_THROUGH: '#a6adc8',
    CONDITIONAL_JUMP: '#f38ba8',
    UNCONDITIONAL_JUMP: '#a6e3a1',
    UNCONDITIONAL_CALL: '#89b4fa',
};

const CFG_BLOCK_WIDTH = 132;
const CFG_BLOCK_HEIGHT = 68;

const layoutCFG = async (cfgNodes, cfgEdges) => {
    const nodeIds = new Set(cfgNodes.map((n) => n.id));
    const validEdges = cfgEdges.filter((e) => nodeIds.has(e.src) && nodeIds.has(e.dst));

    const elkGraph = {
        id: 'cfg-root',
        layoutOptions: {
            'elk.algorithm': 'layered',
            'elk.direction': 'DOWN',
            'elk.spacing.nodeNode': '70',
            'elk.spacing.edgeNode': '30',
            'elk.spacing.edgeEdge': '24',
            'elk.layered.spacing.nodeNodeBetweenLayers': '90',
            'elk.padding': '[24,24,24,24]',
            'elk.layered.edgeRouting': 'ORTHOGONAL',
        },
        children: cfgNodes.map((n) => ({
            id: n.id,
            width: CFG_BLOCK_WIDTH,
            height: CFG_BLOCK_HEIGHT,
        })),
        edges: validEdges.map((e, i) => ({
            id: `cfg-e-${i}`,
            sources: [e.src],
            targets: [e.dst],
        })),
    };

    const laid = await elk.layout(elkGraph);
    const posMap = new Map();
    laid.children.forEach((c) => posMap.set(c.id, { x: c.x, y: c.y }));
    return posMap;
};

// Mini CFG node styled like the main graph's CFGNode
const MiniCFGNode = ({ data }) => (
    <div
        className="node-base"
        style={{
            width: CFG_BLOCK_WIDTH,
            height: CFG_BLOCK_HEIGHT,
            backgroundColor: 'rgba(26, 29, 41, 0.55)',
        }}
    >
        <div className="flex flex-col justify-center items-center w-full h-full px-1 py-1">
            <span className="FuncName text-center truncate w-full" style={{ fontSize: 10, fontWeight: 700 }}>
                {data.blockLabel}
            </span>
            <div className="border-b border-node-border w-full mx-1" />
            <span className="address text-center truncate w-full" style={{ fontSize: 9 }}>
                {data.address}
            </span>
            {data.size && (
                <span className="text-center truncate w-full" style={{ fontSize: 8 }}>
                    {data.size}
                </span>
            )}
        </div>
        <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
        <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
    </div>
);

const miniNodeTypes = { cfgBlock: MiniCFGNode };

const MiniCFG = ({ cfgData, nameMap }) => {
    const [rfNodes, setRfNodes] = useState([]);
    const [rfEdges, setRfEdges] = useState([]);

    useEffect(() => {
        if (!cfgData?.nodes?.length) return;

        const build = async () => {
            const nodeIds = new Set(cfgData.nodes.map((n) => n.id));
            const validEdges = cfgData.edges.filter((e) => nodeIds.has(e.src) && nodeIds.has(e.dst));

            const posMap = await layoutCFG(cfgData.nodes, validEdges);

            const nodes = cfgData.nodes.map((n, idx) => ({
                id: n.id,
                type: 'cfgBlock',
                position: posMap.get(n.id) || { x: 0, y: 0 },
                data: {
                    blockLabel: `Block ${idx + 1}`,
                    address: n.start !== undefined ? n.start : n.id ?? 'unknown',
                    size: n.size ? `${n.size} bytes` : null,
                },
            }));

            const edges = validEdges.map((e, i) => {
                const isCall = e.type === 'UNCONDITIONAL_CALL';
                const calleeName = isCall ? nameMap.get(e.dst) : null;
                const label = isCall && calleeName ? `${e.type} ${calleeName}` : e.type;

                return {
                    id: `cfg-e-${i}`,
                    source: e.src,
                    target: e.dst,
                    style: { stroke: EDGE_COLORS[e.type] || '#a6adc8', strokeWidth: 1.5 },
                    animated: isCall,
                    label,
                    labelStyle: { fill: '#d8dee9', fontSize: 8.5, fontWeight: 500 },
                    labelBgStyle: { fill: '#0f1118', fillOpacity: 0.82, stroke: '#1d2230' },
                    labelBgPadding: [5, 2],
                };
            });

            setRfNodes(nodes);
            setRfEdges(edges);
        };

        build();
    }, [cfgData, nameMap]);

    if (!rfNodes.length) return null;

    return (
        <ReactFlowProvider>
            <ReactFlow
                nodes={rfNodes}
                edges={rfEdges}
                nodeTypes={miniNodeTypes}
                nodesDraggable={false}
                nodesConnectable={false}
                elementsSelectable={false}
                minZoom={0.1}
                panOnDrag
                zoomOnScroll
                colorMode="dark"
                fitView
                fitViewOptions={{ padding: 0.38 }}
                proOptions={{ hideAttribution: true }}
            >
                <Background gap={20} size={0.32} color="#2b303d" />
            </ReactFlow>
        </ReactFlowProvider>
    );
};

const INFO_FIELDS = [
    { key: 'name', label: 'Name' },
    { key: 'type', label: 'Type' },
    { key: 'isEntry', label: 'Entry Point' },
    { key: 'isMajor', label: 'Major Node' },
    { key: 'connectionCount', label: 'Connections' },
];

const accordionClassNames = {
    trigger: 'justify-start',
    title: 'text-base font-semibold text-left text-white',
    content: 'max-h-[300px] overflow-y-auto overflow-x-hidden relative node-scrollbar',
    indicator: 'text-white transition-transform duration-200 data-[open=true]:-rotate-90',
};

const NodePanel = () => {
    const { activePanel, panels, panelWidth } = useCFGNodeStore();
    const { analysisData, getCFG } = useAnalysisStore();
    const [shouldRender, setShouldRender] = useState(false);
    const [isVisible, setIsVisible] = useState(false);
    const [currentPanel, setCurrentPanel] = useState(null);
    const [currentData, setCurrentData] = useState(null);

    const hasActivePanel = activePanel && panels[activePanel];

    useEffect(() => {
        let timer;
        let rafId;
        if (hasActivePanel) {
            setCurrentPanel(activePanel);
            setCurrentData(panels[activePanel]);
            setShouldRender(true);
            rafId = requestAnimationFrame(() => {
                rafId = requestAnimationFrame(() => {
                    setIsVisible(true);
                });
            });
        } else {
            setIsVisible(false);
            timer = setTimeout(() => {
                setShouldRender(false);
                setCurrentPanel(null);
                setCurrentData(null);
            }, 300);
        }
        return () => {
            clearTimeout(timer);
            cancelAnimationFrame(rafId);
        };
    }, [hasActivePanel, activePanel, panels]);

    const decompiledCode = useMemo(() => {
        if (!currentPanel || !analysisData?.decompiled) return null;
        return analysisData.decompiled[currentPanel] ?? null;
    }, [currentPanel, analysisData]);

    const cfgData = useMemo(() => {
        if (!currentPanel || !getCFG) return null;
        return getCFG(currentPanel);
    }, [currentPanel, getCFG]);

    // Build address → function name lookup from the call graph
    const nameMap = useMemo(() => {
        const map = new Map();
        if (analysisData?.callGraph?.nodes) {
            Object.entries(analysisData.callGraph.nodes).forEach(([addr, info]) => {
                if (info.name) map.set(addr, info.name);
            });
        }
        return map;
    }, [analysisData]);

    if (!shouldRender || !currentData) return null;

    return (
        <div
            className={`fixed top-0 right-0 h-screen bg-primary flex z-50
                        origin-right transition-transform duration-300 ease-in-out
                        ${isVisible ? 'scale-x-100' : 'scale-x-0'}`}
            style={{ width: panelWidth }}
        >
            <NodePanelResizeHandle />
            <div className="flex-1 overflow-auto node-scrollbar">
                {/* Accordion content */}
                <div className="px-3 pt-4 pb-4">
                    <Accordion selectionMode="multiple" className="flex flex-col gap-2">
                        {/* Function Info */}
                        <AccordionItem
                            key="info"
                            aria-label="Function Info"
                            title="Function Info"
                            classNames={accordionClassNames}
                        >
                            <div className="space-y-1 text-sm">
                                <div className="node-panel-field">
                                    <span className="node-panel-key">Address</span>
                                    <span className="node-panel-value font-mono">{currentPanel}</span>
                                </div>
                                {INFO_FIELDS.map(({ key, label }) => {
                                    const val = currentData[key] ?? currentData.meta?.[key];
                                    if (val === undefined || val === null) return null;
                                    const display = typeof val === 'boolean' ? (val ? 'Yes' : 'No') : String(val);
                                    return (
                                        <div key={key} className="node-panel-field">
                                            <span className="node-panel-key">{label}</span>
                                            <span className="node-panel-value">{display}</span>
                                        </div>
                                    );
                                })}
                            </div>
                        </AccordionItem>

                        {/* Decompiled Code */}
                        <AccordionItem
                            key="decompiled"
                            aria-label="Decompiled Code"
                            title="Decompiled Code"
                            classNames={{
                                ...accordionClassNames,
                                content: 'max-h-[400px] overflow-y-auto overflow-x-auto relative node-scrollbar',
                            }}
                        >
                            {decompiledCode ? (
                                <pre className="md-pre">
                                    <code className="md-code-block">{typeof decompiledCode === 'string' ? decompiledCode : JSON.stringify(decompiledCode, null, 2)}</code>
                                </pre>
                            ) : (
                                <div className="text-gray-500 text-sm py-4 text-center">
                                    No decompilation available
                                </div>
                            )}
                        </AccordionItem>

                        {/* Control Flow Graph */}
                        <AccordionItem
                            key="cfg"
                            aria-label="Control Flow Graph"
                            title="Control Flow Graph"
                        classNames={{
                            ...accordionClassNames,
                            content: 'max-h-[520px] overflow-y-auto overflow-x-hidden relative node-scrollbar',
                        }}
                    >
                        {cfgData && cfgData.nodes?.length > 0 ? (
                            <div className="h-100 w-full py-3 px-2 space-y-4">
                                <div className="h-100 w-full py-3 px-3">
                                    <MiniCFG cfgData={cfgData} nameMap={nameMap} />
                                </div>
                            </div>
                        ) : (
                            <div className="text-gray-500 text-sm py-4 text-center">
                                No CFG available
                            </div>
                            )}
                        </AccordionItem>
                    </Accordion>
                </div>
            </div>
        </div>
    );
};

export default NodePanel;
