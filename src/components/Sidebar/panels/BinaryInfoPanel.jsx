
const defaultContent = 1
const BinaryOverview = () => { 
    return (
        <div className="px-4 py-3 text-sm text-gray-200 space-y-4">
      
      {/* Program Info */}
      <section>
        <h2 className="text-xs font-semibold uppercase tracking-wide text-gray-400
                       border-b border-white/10 pb-1 mb-2">
          Program Info
        </h2>

        <ul className="space-y-1 pl-4">
          <li className="flex justify-between">
            <span>Architecture</span>
            <span className="font-mono text-gray-400">x86_64</span>
          </li>
          <li className="flex justify-between">
            <span>Format</span>
            <span className="font-mono text-gray-400">Mach-O</span>
          </li>
          <li className="flex justify-between">
            <span>Bits</span>
            <span className="font-mono text-gray-400">64</span>
          </li>
          <li className="flex justify-between">
            <span>Entry Point</span>
            <span className="font-mono text-gray-400">0x100000…</span>
          </li>
        </ul>
      </section>

      {/* Memory Layout */}
      <section>
        <h2 className="text-xs font-semibold uppercase tracking-wide text-gray-400
                       border-b border-white/10 pb-1 mb-2">
          Memory Layout
        </h2>

        <ul className="space-y-1 pl-4">
          <li className="flex justify-between">
            <span>Image Base</span>
            <span className="font-mono text-gray-400">0x100000000</span>
          </li>
          <li className="flex justify-between">
            <span>Min Address</span>
            <span className="font-mono text-gray-400">0x100004…</span>
          </li>
          <li className="flex justify-between">
            <span>Max Address</span>
            <span className="font-mono text-gray-400">0x10000…</span>
          </li>
          <li className="flex justify-between">
            <span>Virtual Size</span>
            <span className="font-mono text-gray-400">0x16000</span>
          </li>
        </ul>
      </section>

      {/* Protections */}
      <section>
        <h2 className="text-xs font-semibold uppercase tracking-wide text-gray-400
                       border-b border-white/10 pb-1 mb-2">
          Protections
        </h2>

        <ul className="space-y-1 pl-4">
          <li className="flex justify-between">
            <span>PIE</span>
            <span className="text-green-400">Enabled</span>
          </li>
          <li className="flex justify-between">
            <span>NX</span>
            <span className="text-green-400">Enabled</span>
          </li>
          <li className="flex justify-between">
            <span>NX</span>
            <span className="text-green-400">Enabled</span>
          </li>
          <li className="flex justify-between">
            <span>NX</span>
            <span className="text-green-400">Enabled</span>
          </li>
          <li className="flex justify-between">
            <span>Encrypted</span>
            <span className="text-gray-400">No</span>
          </li>
        </ul>
      </section>

    </div>
    );
}

export default BinaryOverview
