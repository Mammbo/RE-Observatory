import useAnalysisStore from "../../../store/analysisStore";
import {
    HiShieldCheck,
    HiShieldExclamation,
    HiMinus
} from "react-icons/hi2";

// Security badge component
const SecurityBadge = ({ enabled, label }) => {
    if (enabled === null || enabled === undefined) {
        return (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-gray-700/50 text-gray-400">
                <HiMinus className="w-3 h-3" />
                {label}
            </span>
        );
    }
    return enabled ? (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-green-900/50 text-green-400 border border-green-700/50">
            <HiShieldCheck className="w-3 h-3" />
            {label}
        </span>
    ) : (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-red-900/50 text-red-400 border border-red-700/50">
            <HiShieldExclamation className="w-3 h-3" />
            {label}
        </span>
    );
};

// Status indicator for simple enabled/disabled
const StatusIndicator = ({ value, trueText = "Enabled", falseText = "Disabled", nullText = "N/A" }) => {
    if (value === null || value === undefined) {
        return <span className="text-gray-500">{nullText}</span>;
    }
    return value ? (
        <span className="text-green-400">{trueText}</span>
    ) : (
        <span className="text-gray-400">{falseText}</span>
    );
};

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

// Truncate hex addresses for display
const truncateHex = (hex, maxLen = 12) => {
    if (!hex) return "—";
    if (hex.length <= maxLen) return hex;
    return hex.slice(0, maxLen) + "…";
};

const BinaryOverview = () => {
    const { analysisData, isLoading } = useAnalysisStore();
    const meta = analysisData?.programInfo?.meta;
    const security = meta?.security;

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

    const format = security?.format || meta?.format;

    return (
        <div className="px-4 py-3 text-sm text-gray-200 space-y-4 overflow-y-auto max-h-[calc(100vh-80px)]">

            {/* Program Info */}
            <section>
                <SectionHeader>Program Info</SectionHeader>
                <ul className="space-y-1.5">
                    <InfoRow label="Name" value={meta.name} mono={false} />
                    <InfoRow label="Format" value={format} />
                    <InfoRow label="Architecture" value={meta.architecture} />
                    <InfoRow label="Bits" value={meta.bits} />
                    <InfoRow label="Entry Point" value={truncateHex(meta.entrypoint)} />
                </ul>
            </section>

            {/* Memory Layout */}
            <section>
                <SectionHeader>Memory Layout</SectionHeader>
                <ul className="space-y-1.5">
                    <InfoRow label="Image Base" value={truncateHex(meta.image_base)} />
                    <InfoRow label="Min Address" value={truncateHex(meta.min_address)} />
                    <InfoRow label="Max Address" value={truncateHex(meta.max_address)} />
                    <InfoRow label="Virtual Size" value={truncateHex(meta.virtual_size)} />
                    <InfoRow label="Original Size" value={meta.original_size ? `${(meta.original_size / 1024).toFixed(1)} KB` : "—"} />
                </ul>
            </section>

            {/* Core Security Features */}
            {security && (
                <section>
                    <SectionHeader>Security Features</SectionHeader>
                    <div className="flex flex-wrap gap-1.5 mb-3">
                        <SecurityBadge enabled={security.pie} label="PIE" />
                        <SecurityBadge enabled={security.nx} label="NX" />
                        <SecurityBadge enabled={security.aslr} label="ASLR" />
                        <SecurityBadge enabled={security.stack_canary} label="Canary" />
                        {security.relro && (
                            <SecurityBadge
                                enabled={security.relro === "full" || security.relro === "partial"}
                                label={`RELRO (${security.relro})`}
                            />
                        )}
                    </div>

                    {/* RWX Sections Warning */}
                    {security.rwx_sections && security.rwx_sections.length > 0 && (
                        <div className="bg-red-900/30 border border-red-700/50 rounded px-2 py-1.5 mb-3">
                            <p className="text-xs text-red-400 font-medium">W+X Sections Detected</p>
                            <p className="text-xs text-red-300/70 font-mono">{security.rwx_sections.join(", ")}</p>
                        </div>
                    )}
                </section>
            )}

            {/* PE-Specific Features */}
            {security?.pe && (
                <section>
                    <SectionHeader>PE Security</SectionHeader>
                    <div className="flex flex-wrap gap-1.5 mb-2">
                        <SecurityBadge enabled={security.pe.dep} label="DEP" />
                        <SecurityBadge enabled={security.pe.control_flow_guard} label="CFG" />
                        <SecurityBadge enabled={security.pe.high_entropy_va} label="HEVA" />
                        {security.pe.safe_seh !== undefined && (
                            <SecurityBadge enabled={security.pe.safe_seh} label="SafeSEH" />
                        )}
                        {security.pe.xfg && <SecurityBadge enabled={true} label="XFG" />}
                        {security.pe.rf_guard && <SecurityBadge enabled={true} label="RFG" />}
                    </div>
                    <ul className="space-y-1.5 text-xs">
                        <li className="flex justify-between">
                            <span>Signed</span>
                            <StatusIndicator value={security.pe.signed} trueText="Yes" falseText="No" />
                        </li>
                        {security.pe.signed && (
                            <li className="flex justify-between">
                                <span>Signature Valid</span>
                                <StatusIndicator value={security.pe.signature_valid} trueText="Valid" falseText="Invalid" />
                            </li>
                        )}
                        <li className="flex justify-between">
                            <span>Security Cookie</span>
                            <StatusIndicator value={security.pe.security_cookie} />
                        </li>
                        <li className="flex justify-between">
                            <span>Isolation</span>
                            <StatusIndicator value={security.pe.isolation} />
                        </li>
                        <li className="flex justify-between">
                            <span>AppContainer</span>
                            <StatusIndicator value={security.pe.appcontainer} />
                        </li>
                    </ul>
                </section>
            )}

            {/* ELF-Specific Features */}
            {security?.elf && (
                <section>
                    <SectionHeader>ELF Security</SectionHeader>
                    <div className="flex flex-wrap gap-1.5 mb-2">
                        <SecurityBadge enabled={security.elf.bind_now} label="BIND_NOW" />
                        <SecurityBadge enabled={security.elf.fortify_source} label="Fortify" />
                        <SecurityBadge enabled={security.elf.ibt} label="IBT" />
                        <SecurityBadge enabled={security.elf.shadow_stack} label="SHSTK" />
                        <SecurityBadge enabled={!security.elf.executable_stack} label="NX Stack" />
                    </div>
                    <ul className="space-y-1.5 text-xs">
                        {security.elf.rpath && (
                            <li className="flex justify-between">
                                <span>RPATH</span>
                                <span className="text-yellow-400 truncate max-w-30" title={security.elf.rpath}>
                                    {security.elf.rpath}
                                </span>
                            </li>
                        )}
                        {security.elf.runpath && (
                            <li className="flex justify-between">
                                <span>RUNPATH</span>
                                <span className="text-yellow-400 truncate max-w-30" title={security.elf.runpath}>
                                    {security.elf.runpath}
                                </span>
                            </li>
                        )}
                    </ul>
                    {security.elf.fortify_functions && security.elf.fortify_functions.length > 0 && (
                        <div className="mt-2 bg-gray-800/50 rounded px-2 py-1.5">
                            <p className="text-xs text-gray-400 mb-1">Fortified Functions ({security.elf.fortify_functions.length})</p>
                            <p className="text-xs text-gray-500 font-mono truncate" title={security.elf.fortify_functions.join(", ")}>
                                {security.elf.fortify_functions.slice(0, 3).join(", ")}
                                {security.elf.fortify_functions.length > 3 && "..."}
                            </p>
                        </div>
                    )}
                </section>
            )}

            {/* Mach-O Specific Features */}
            {security?.macho && (
                <section>
                    <SectionHeader>Mach-O Security</SectionHeader>
                    <div className="flex flex-wrap gap-1.5 mb-2">
                        <SecurityBadge enabled={security.macho.code_signed} label="Signed" />
                        <SecurityBadge enabled={security.macho.arm64e_pac} label="PAC" />
                        <SecurityBadge enabled={security.macho.restrict_segment} label="Restrict" />
                        <SecurityBadge enabled={!security.macho.allow_stack_execution} label="NX Stack" />
                        <SecurityBadge enabled={security.macho.no_heap_execution} label="NX Heap" />
                    </div>
                    <ul className="space-y-1.5 text-xs">
                        <li className="flex justify-between">
                            <span>Encrypted</span>
                            <StatusIndicator value={security.macho.encrypted} trueText="Yes" falseText="No" />
                        </li>
                        <li className="flex justify-between">
                            <span>Root Safe</span>
                            <StatusIndicator value={security.macho.root_safe} />
                        </li>
                        <li className="flex justify-between">
                            <span>Setuid Safe</span>
                            <StatusIndicator value={security.macho.setuid_safe} />
                        </li>
                        <li className="flex justify-between">
                            <span>App Extension Safe</span>
                            <StatusIndicator value={security.macho.app_extension_safe} />
                        </li>
                    </ul>
                    {/* RWX Segments Warning */}
                    {security.macho.rwx_segments && security.macho.rwx_segments.length > 0 && (
                        <div className="mt-2 bg-red-900/30 border border-red-700/50 rounded px-2 py-1.5">
                            <p className="text-xs text-red-400 font-medium">W+X Segments Detected</p>
                            <p className="text-xs text-red-300/70 font-mono">{security.macho.rwx_segments.join(", ")}</p>
                        </div>
                    )}
                </section>
            )}

            {/* Stats Summary */}
            <section>
                <SectionHeader>Summary</SectionHeader>
                <div className="grid grid-cols-3 gap-2 text-center">
                    <div className="bg-gray-800/50 rounded p-2">
                        <div className="text-lg font-bold ">{meta.imports?.length ?? 0}</div>
                        <div className="text-xs text-gray-500">Imports</div>
                    </div>
                    <div className="bg-gray-800/50 rounded p-2">
                        <div className="text-lg font-bold ">{meta.exports?.length ?? 0}</div>
                        <div className="text-xs text-gray-500">Exports</div>
                    </div>
                    <div className="bg-gray-800/50 rounded p-2">
                        <div className="text-lg font-bold">{meta.libraries?.length ?? 0}</div>
                        <div className="text-xs text-gray-500">Libraries</div>
                    </div>
                </div>
            </section>

        </div>
    );
};

export default BinaryOverview;
