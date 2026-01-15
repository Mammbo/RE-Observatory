import { ReactFlow, Background, Controls, applyEdgeChanges, applyNodeChanges, addEdge, SelectionMode } from '@xyflow/react';
import { useState, useCallback } from 'react';
import '@xyflow/react/dist/style.css';

// make a react hook that generates the amount of nodes edges and labels needed with the information needed per function.
const initialNodes = [
  {
    id: 'n1',
    position: { x: 0, y: 0 },
    data: { label: 'Node 1' },
    type: 'input',
  },
  {
    id: 'n2',
    position: { x: 100, y: 100 },
    data: { label: 'Node 2' },
  },
];

const initialEdges = [
 
];


// create nodes that can be had as notes

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
                <ReactFlow
                    nodes={nodes}
                    edges={edges}
                    onNodesChange={onNodesChange}
                    onEdgesChange={onEdgesChange}
                    onConnect={onConnect}
                    fitView
                    >
                    <Background />
                    <Controls />
                </ReactFlow>
            </div>
    );
};

export default CanvasView;