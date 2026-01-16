import { ReactFlow, Controls, ControlButton, useReactFlow } from '@xyflow/react';
import '@xyflow/react/dist/style.css';


const AddNodeButton = () => {

    const handleAddNode = () => { 

    }
  return (
    <ReactFlow nodes={[]} edges={[]} onInit={(reactFlowInstance) => {
      // Optional: initialize flow
    }}>
      <Controls>
        <AddNodeButton />
      </Controls>
    </ReactFlow>
  );
}   

export default Flow;