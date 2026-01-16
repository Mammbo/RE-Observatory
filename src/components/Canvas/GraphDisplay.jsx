import { ReactFlow, ReactFlowProvider, Background, Controls, applyEdgeChanges, applyNodeChanges, addEdge, SelectionMode, MiniMap, Panel } from '@xyflow/react';
import { useState, useCallback } from 'react';
import '@xyflow/react/dist/style.css';
import NoteNode from './NoteNode';

// make a react hook that generates the amount of nodes edges and labels needed with the information needed per function.
const initialNodes = [
  {
    id: 'n1',
    type: 'note',
    position: { x: 0, y: 0 },
    data: { label: 'Node 1' },
  },
  {
    id: 'n2',
    position: { x: 100, y: 100 },
    data: { label: 'Node 2' },
  },
];

const initialEdges = [
 
];
const nodeTypes = { 
        note: NoteNode,
    }


// create nodes that can be had as notes

// create minimap with node color functionality

const CanvasView = () => { 
    const [nodes, setNodes] = useState(initialNodes);
    const [edges, setEdges] = useState(initialEdges);
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
    return (
            <div className='w-full h-full'>
                <ReactFlowProvider>
                    <ReactFlow
                        nodes={nodes}
                        edges={edges}
                        nodeTypes={nodeTypes}
                        onNodesChange={onNodesChange}
                        onEdgesChange={onEdgesChange}
                        onConnect={onConnect}
                        selectionMode={SelectionMode.Partial}
                        colorMode='dark'
                        fitView
                        >
                        <Panel position="top-center">Reverse Engineering Observatory</Panel>

                        <MiniMap nodeStrokeWidth={3} zoomable pannable />
                        <Background />
                        <Controls />
                    </ReactFlow>
                </ReactFlowProvider>
            </div>
    );
};

export default CanvasView;