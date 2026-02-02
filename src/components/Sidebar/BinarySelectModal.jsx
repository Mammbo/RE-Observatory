import { useEffect, useState } from 'react';

const BinarySelectModal = ({ onClose, onUploadNew }) => {
    const [binaries, setBinaries] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        let mounted = true;

        window.electron.sendAsync('list_binaries', {});

        window.electron.onMessage((message) => {
            if (!mounted) return;
            if (message.type === 'binary_list') {
                setBinaries(message.payload.binaries || []);
                setLoading(false);
            }
        });

        return () => { mounted = false; };
    }, []);

    const handleLoadBinary = (binaryId) => {
        window.electron.sendAsync('load_binary', { binary_id: binaryId });
        onClose();
    };

    const handleUploadNew = () => {
        onUploadNew();
        onClose();
    };

    return (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 backdrop-blur-sm" onClick={onClose}>
            <div className="bg-secondary border border-border-default rounded-lg shadow-2xl w-[500px] max-h-[70vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-border-default">
                    <h2 className="text-lg font-semibold text-text-primary">Open Binary</h2>
                    <button onClick={onClose} className="text-text-secondary hover:text-text-primary transition-colors text-xl leading-none">&times;</button>
                </div>

                {/* Upload new */}
                <div className="px-6 py-4 border-b border-border-default">
                    <button
                        onClick={handleUploadNew}
                        className="w-full py-2.5 rounded-md bg-accent hover:bg-accent-hover text-primary font-medium transition-colors"
                    >
                        Upload New Binary
                    </button>
                </div>

                {/* Previous analyses */}
                <div className="px-6 py-3">
                    <h3 className="text-sm font-medium text-text-secondary uppercase tracking-wider mb-2">Previous Analyses</h3>
                </div>
                <div className="flex-1 overflow-y-auto px-6 pb-4">
                    {loading ? (
                        <div className="flex justify-center py-8">
                            <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
                        </div>
                    ) : binaries.length === 0 ? (
                        <p className="text-text-secondary text-sm text-center py-8">No previous analyses found.</p>
                    ) : (
                        <div className="space-y-2">
                            {binaries.map((bin) => (
                                <button
                                    key={bin.id}
                                    onClick={() => handleLoadBinary(bin.id)}
                                    className="w-full text-left px-4 py-3 rounded-md bg-primary hover:bg-primary/70 border border-border-default hover:border-accent transition-colors group"
                                >
                                    <div className="flex items-center justify-between">
                                        <span className="text-text-primary font-medium group-hover:text-accent transition-colors">{bin.name}</span>
                                        <span className="text-xs text-text-secondary">{bin.format}</span>
                                    </div>
                                    <div className="flex items-center justify-between mt-1">
                                        <span className="text-xs text-text-secondary truncate max-w-[280px]">{bin.filepath}</span>
                                        <span className="text-xs text-text-secondary">{bin.architecture}</span>
                                    </div>
                                    {bin.created_at && (
                                        <div className="text-xs text-text-secondary mt-1">{new Date(bin.created_at).toLocaleString()}</div>
                                    )}
                                </button>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default BinarySelectModal;
