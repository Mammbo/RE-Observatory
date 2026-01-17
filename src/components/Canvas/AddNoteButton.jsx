import { ControlButton, useReactFlow } from '@xyflow/react';
import { FiPlus } from 'react-icons/fi';

const AddNodeButton = () => {
    const reactFlow = useReactFlow();

    const handleAddNode = () => {
        reactFlow.addNodes({
            id: `node-${Date.now()}`,
            type: 'note',
            position: { x: 100, y: 100 },
            data: { label: 'New Note' },
        });
    };

    return (
        <ControlButton onClick={handleAddNode} title="Add Note">
            <FiPlus />
        </ControlButton>
    );
};

export default AddNodeButton;