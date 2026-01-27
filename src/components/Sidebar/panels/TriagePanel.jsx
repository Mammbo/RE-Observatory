import useAnalysisStore from "../../../store/analysisStore";
import { Accordion, AccordionItem } from "@heroui/accordion";

// Section header component
const SectionHeader = ({ children }) => (
    <h2 className="text-xs font-semibold uppercase tracking-wide text-gray-400 border-b border-white/10 pb-1 mb-2">
        {children}
    </h2>
);

// Info row component
const InfoRow = ({ label, value, mono = true }) => (
    <li className="flex justify-between items-center">
        <span className="text-gray-300">{label}</span>
        <span className={`${mono ? 'font-mono' : ''} text-gray-400 truncate ml-2 max-w-35`} title={value}>
            {value ?? "—"}
        </span>
    </li>
);

const TriageOverview = () => { 
    const { analysisData, isLoading } = useAnalysisStore(); 
    const meta = analysisData?.programInfo?.meta;
    if (isLoading) { 
        return (
            <div className="px-4 py-8 text-center">
                <div className="animate-spin w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-3"></div>
                <p className="text-sm text-gray-400">Analyzing binary...</p>
            </div>
        );
    }

    if (!meta) {
        return (
            <div className="px-4 py-8 text-center text-gray-500 text-sm">
                <p>No binary loaded</p>
                <p className="text-xs mt-1">Select a binary to view its information</p>
            </div>
        );
    }

    return ( 
        <div 
        className={" px-4 py-3 text-sm text-gray-200 space-y-4"}>
            <Accordion selectionMode="multiple">
                <AccordionItem
                    key="1"
                    aria-label="Imports"
                    title="Imports"
                    classNames={{
                        trigger: "justify-start",
                        title: "text-base font-semibold text-left",
                        content: "max-h-[200px] overflow-y-auto"
                    }}
                >
                    {meta.imports.map((item, index) => {
                        return ( 
                            <div key={index}>
                                {item.name} - {item.address}
                            </div>
                        ) 
                    })}
                </AccordionItem>
            </Accordion>
        </div>
    );
}

export default TriageOverview;