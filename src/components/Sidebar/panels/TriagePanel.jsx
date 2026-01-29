import useAnalysisStore from "../../../store/analysisStore";
import { Accordion, AccordionItem } from "@heroui/accordion";
import SearchBar from "./SearchBar";



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
            <div> 
                <h1>SearchBar</h1>
                <SearchBar data={meta}/> 
            </div>
            <Accordion selectionMode="multiple" className="flex flex-col gap-3">
                <AccordionItem
                    key="1"
                    aria-label="Imports"
                    title="Imports"
                    classNames={{
                        trigger: "justify-start",
                        title: "text-base font-semibold text-left",
                        content: "max-h-[200px] overflow-y-auto overflow-x-hidden relative node-scrollbar",
                        indicator: "transition-transform duration-200 data-[open=true]:-rotate-90"
                    }}
                >
                    <div className="px-1 py-1 text-[10px] uppercase tracking-wide text-gray-400 border-b border-white/10">
                        <div className="grid grid-cols-2 gap-3">
                            <span>Function</span>
                            <span className="text-right">Address</span>
                        </div>
                    </div>
                    <div className="pt-2 space-y-1">
                        {meta.imports?.length > 0 ? (
                            meta.imports.map((item, index) => (
                                <div key={index} className="grid grid-cols-2 gap-3">
                                    <span className="truncate">{item.name}</span>
                                    <span className="font-mono text-gray-400 text-right">{item.address}</span>
                                </div>
                            ))
                        ) : (
                            <div className="text-gray-500 text-sm py-2">No imports found</div>
                        )}
                    </div>
                </AccordionItem>

                <AccordionItem
                    key="2"
                    aria-label="Exports"
                    title="Exports"
                    classNames={{
                        trigger: "justify-start",
                        title: "text-base font-semibold text-left",
                        content: "max-h-[200px] overflow-y-auto overflow-x-hidden relative node-scrollbar",
                        indicator: "transition-transform duration-200 data-[open=true]:-rotate-90"
                    }}
                >
                    <div className="px-1 py-1 text-[10px] uppercase tracking-wide text-gray-400 border-b border-white/10">
                        <div className="grid grid-cols-2 gap-3">
                            <span>Function</span>
                            <span className="text-right">Address</span>
                        </div>
                    </div>
                    <div className="pt-2 space-y-1">
                        {meta.exports?.length > 0 ? (
                            meta.exports.map((item, index) => (
                                <div key={index} className="grid grid-cols-2 gap-3">
                                    <span className="truncate">{item.name}</span>
                                    <span className="font-mono text-gray-400 text-right">{item.address}</span>
                                </div>
                            ))
                        ) : (
                            <div className="text-gray-500 text-sm py-2">No exports found</div>
                        )}
                    </div>
                </AccordionItem>

                <AccordionItem
                    key="3"
                    aria-label="Libraries"
                    title="Libraries"
                    classNames={{
                        trigger: "justify-start",
                        title: "text-base font-semibold text-left",
                        content: "max-h-[200px] overflow-y-auto overflow-x-hidden relative node-scrollbar",
                        indicator: "transition-transform duration-200 data-[open=true]:-rotate-90"
                    }}
                >
                    <div className="px-1 py-1 text-[10px] uppercase tracking-wide text-gray-400 border-b border-white/10">
                        <div className="grid grid-cols-3 gap-3">
                            <span>Name</span>
                            <span className="text-center">Current Version</span>
                            <span className="text-right">Compatibility Version</span>
                        </div>
                    </div>
                    <div className="pt-2 space-y-1">
                        {meta.libraries?.length > 0 ? (
                            meta.libraries.map((item, index) => (
                                <div key={index} className="grid grid-cols-3 gap-3">
                                    <span className="truncate">{item.name}</span>
                                    <span className="font-mono text-gray-400 text-center">{item.current_version?.join('.')}</span>
                                    <span className="font-mono text-gray-400 text-right">{item.compatibility_version?.join('.')}</span>
                                </div>
                            ))
                        ) : (
                            <div className="text-gray-500 text-sm py-2">No libraries found</div>
                        )}
                    </div>
                </AccordionItem>

                <AccordionItem
                    key="4"
                    aria-label="ASCII Strings"
                    title="ASCII Strings"
                    classNames={{
                        trigger: "justify-start",
                        title: "text-base font-semibold text-left",
                        content: "max-h-[200px] overflow-y-auto overflow-x-hidden relative node-scrollbar",
                        indicator: "transition-transform duration-200 data-[open=true]:-rotate-90"
                    }}
                >
                    <div className="px-1 py-1 text-[10px] uppercase tracking-wide text-gray-400 border-b border-white/10">
                        <span>String</span>
                    </div>
                    <div className="pt-2 space-y-1">
                        {meta.strings?.static?.ascii?.length > 0 ? (
                            meta.strings.static.ascii.map((str, index) => (
                                <div key={index} className="truncate font-mono text-gray-300">
                                    {str}
                                </div>
                            ))
                        ) : (
                            <div className="text-gray-500 text-sm py-2">No ASCII strings found</div>
                        )}
                    </div>
                </AccordionItem>

                <AccordionItem
                    key="5"
                    aria-label="UTF-16 Strings"
                    title="UTF-16 Strings"
                    classNames={{
                        trigger: "justify-start",
                        title: "text-base font-semibold text-left",
                        content: "max-h-[200px] overflow-y-auto overflow-x-hidden relative node-scrollbar",
                        indicator: "transition-transform duration-200 data-[open=true]:-rotate-90"
                    }}
                >
                    <div className="px-1 py-1 text-[10px] uppercase tracking-wide text-gray-400 border-b border-white/10">
                        <span>String</span>
                    </div>
                    <div className="pt-2 space-y-1">
                        {meta.strings?.static?.utf16?.length > 0 ? (
                            meta.strings.static.utf16.map((str, index) => (
                                <div key={index} className="truncate font-mono text-gray-300">
                                    {str}
                                </div>
                            ))
                        ) : (
                            <div className="text-gray-500 text-sm py-2">No UTF-16 strings found</div>
                        )}
                    </div>
                </AccordionItem>

                <AccordionItem
                    key="6"
                    aria-label="Stack Strings"
                    title="Stack Strings"
                    classNames={{
                        trigger: "justify-start",
                        title: "text-base font-semibold text-left",
                        content: "max-h-[200px] overflow-y-auto overflow-x-hidden relative node-scrollbar",
                        indicator: "transition-transform duration-200 data-[open=true]:-rotate-90"
                    }}
                >
                    <div className="px-1 py-1 text-[10px] uppercase tracking-wide text-gray-400 border-b border-white/10">
                        <span>String</span>
                    </div>
                    <div className="pt-2 space-y-1">
                        {meta.strings?.advanced?.stack?.length > 0 ? (
                            meta.strings.advanced.stack.map((str, index) => (
                                <div key={index} className="truncate font-mono text-gray-300">
                                    {str}
                                </div>
                            ))
                        ) : (
                            <div className="text-gray-500 text-sm py-2">No stack strings found</div>
                        )}
                    </div>
                </AccordionItem>

                <AccordionItem
                    key="7"
                    aria-label="Tight Strings"
                    title="Tight Strings"
                    classNames={{
                        trigger: "justify-start",
                        title: "text-base font-semibold text-left",
                        content: "max-h-[200px] overflow-y-auto overflow-x-hidden relative node-scrollbar",
                        indicator: "transition-transform duration-200 data-[open=true]:-rotate-90"
                    }}
                >
                    <div className="px-1 py-1 text-[10px] uppercase tracking-wide text-gray-400 border-b border-white/10">
                        <span>String</span>
                    </div>
                    <div className="pt-2 space-y-1">
                        {meta.strings?.advanced?.tight?.length > 0 ? (
                            meta.strings.advanced.tight.map((str, index) => (
                                <div key={index} className="truncate font-mono text-gray-300">
                                    {str}
                                </div>
                            ))
                        ) : (
                            <div className="text-gray-500 text-sm py-2">No tight strings found</div>
                        )}
                    </div>
                </AccordionItem>

                <AccordionItem
                    key="8"
                    aria-label="Decoded Strings"
                    title="Decoded Strings"
                    classNames={{
                        trigger: "justify-start",
                        title: "text-base font-semibold text-left",
                        content: "max-h-[200px] overflow-y-auto overflow-x-hidden relative node-scrollbar",
                        indicator: "transition-transform duration-200 data-[open=true]:-rotate-90"
                    }}
                >
                    <div className="px-1 py-1 text-[10px] uppercase tracking-wide text-gray-400 border-b border-white/10">
                        <span>String</span>
                    </div>
                    <div className="pt-2 space-y-1">
                        {meta.strings?.obfuscated?.decode?.length > 0 ? (
                            meta.strings.obfuscated.decode.map((str, index) => (
                                <div key={index} className="truncate font-mono text-gray-300">
                                    {str}
                                </div>
                            ))
                        ) : (
                            <div className="text-gray-500 text-sm py-2">No decoded strings found</div>
                        )}
                    </div>
                </AccordionItem>
            </Accordion>
        </div>
    );
}

export default TriageOverview;
