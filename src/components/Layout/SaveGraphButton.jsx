import { MdSave } from 'react-icons/md';
import useAnalysisStore from '../../store/analysisStore';
import useGraphStore from '../../store/graphStore';
import { useToast } from './Toast';

const SaveGraphButton = () => {
    const binaryId = useAnalysisStore((s) => s.binaryId);
    const { showToast } = useToast();

    const handleSave = () => {
        if (!binaryId) {
            showToast('No binary loaded to save graph for', 'error');
            return;
        }
        const { userNodes, userEdges } = useGraphStore.getState();
        window.electron.sendAsync('save_graph', {
            binary_id: binaryId,
            userNodes,
            userEdges,
        });
    };

    return (
        <button
            onClick={handleSave}
            disabled={!binaryId}
            className={`flex z-50 items-center gap-2 px-3 py-2 rounded-lg
                bg-secondary border border-border-default shadow-lg transition-all duration-200
                ${binaryId
                    ? 'hover:bg-hover hover:border-accent text-text-primary cursor-pointer'
                    : 'opacity-40 cursor-not-allowed text-text-tertiary'}`}
            style={{ WebkitAppRegion: 'no-drag' }}
        >
            <MdSave size={18} />
            <span className="text-xs font-medium">Save</span>
        </button>
    );
};

export default SaveGraphButton;
