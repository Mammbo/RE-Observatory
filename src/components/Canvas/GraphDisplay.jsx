import { ReactFlow, ReactFlowProvider, Background, Controls, applyEdgeChanges, applyNodeChanges, addEdge, SelectionMode, MiniMap } from '@xyflow/react';
import { useState, useCallback } from 'react';
import '@xyflow/react/dist/style.css';
import NoteNode from './NoteNode';
import CFGNode from './CFGNode';
import Flow from './AddNoteButton'

// make a react hook that generates the amount of nodes edges and labels needed with the information needed per function.
// use dagre to render the nodes
const initialNodes = [
  {
    id: 'n1',
    type: 'note',
    position: { x: 0, y: 0 },
    data: { label: 'Node 1' },
  },
  {
    id: 'n2',
    type: 'CFG',
    position: { x: 100, y: 100 },
    data: { src: '0x4010000' },
  },
];

const initialEdges = [
 
];
const nodeTypes = { 
        note: NoteNode,
        CFG: CFGNode
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
                        selectionMode={SelectionMode.Partial}
                        colorMode='dark'
                        fitView
                        >
                        <MiniMap nodeStrokeWidth={3} zoomable pannable />
                        <Background />
                        <Controls>
                            <Flow />    
                        </Controls>    
                    </ReactFlow>
                </ReactFlowProvider>
            </div>
    );
};

export default CanvasView;