import { ControlButton, useReactFlow } from '@xyflow/react';
import { FiPlus } from 'react-icons/fi';
import useGraphStore from '../../store/graphStore';

const AddNodeButton = () => {
    const addUserNode = useGraphStore((s) => s.addUserNode);
    const { screenToFlowPosition } = useReactFlow();

    const handleAddNode = () => {
        // Place the note at the center of the current viewport
        const center = screenToFlowPosition({
            x: window.innerWidth / 2,
            y: window.innerHeight / 2,
        });

        addUserNode({
            id: `note-${Date.now()}`,
            type: 'note',
            position: center,
            data: { label: 'New Note', content: '' },
        });
    };

    return (
        <ControlButton onClick={handleAddNode} title="Add Note">
            <FiPlus />
        </ControlButton>
    );
};

export default AddNodeButton;
