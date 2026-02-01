import { ControlButton } from '@xyflow/react';
import { FiPlus } from 'react-icons/fi';
import useGraphStore from '../../store/graphStore';

const AddNodeButton = () => {
    const addUserNode = useGraphStore((s) => s.addUserNode);

    const handleAddNode = () => {
        addUserNode({
            id: `note-${Date.now()}`,
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