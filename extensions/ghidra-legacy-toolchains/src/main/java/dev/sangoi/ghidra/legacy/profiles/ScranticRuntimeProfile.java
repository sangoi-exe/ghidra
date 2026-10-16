package dev.sangoi.ghidra.legacy.profiles;

import dev.sangoi.ghidra.legacy.ToolchainProfile;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

/** Established member correspondences on one supplied image, not reusable runtime signatures. */
public final class ScranticRuntimeProfile extends ToolchainProfile {
    public static final String ID = "scrantic-runtime-qualified";

    public ScranticRuntimeProfile() {
        super(ID, "New Executable (NE)", 295952, "f0552c281a2a9b367ad5f41402a907a3c99e73ad0a221ba14d063e31cff594ac");
    }

    @Override
    public void prepareData(Context c, TaskMonitor monitor, MessageLog log) throws Exception {
        monitor.checkCancelled();
    }

    @Override
    public void applyFinalFacts(Context c, TaskMonitor monitor, MessageLog log) throws Exception {
        monitor.checkCancelled();
        // Johnny matching annex at fixed cutoff5e6c9dbe, LSEEK599ba65 and R49 heap record.
        // All coordinates below are absolute original FILE; NE1 starts0800, NE13 starts17200.
        c.function(0xde2, 0xe0d, "scrantic_cwm31_lseek_correspondence", 0, "NE1:[05e2,060d), complete43-byte/20-instruction correspondence to the bound Borland3.1 CWM LSEEK member/public _lseek. This is qualified tool-member provenance, not a historical Johnny name or modern lseek ABI. The indexed DS displacement is2af8; the near call at0606 reaches04e8. INT21 effects/meaning, DS-selected memory meanings and vendor-callee equivalence remain unproved.");
        c.label(0xde2, "scrantic_cwm31_lseek_correspondence");
        c.label(0xded, "scrantic_lseek_dgroup_displacement_binding");
        c.comment(0xded, "NE1:05ed, member field+0b: original bound WORD2af8 in the indexed DS operand. Vendor __openfd is a binding role, not an admitted original data name or complete table layout. No runtime DS/selector or indexed extent guarantee.");
        c.label(0xe06, "scrantic_lseek_near_error_binding");
        c.comment(0xe06, "Original E8 dffe at NE1:0606 reaches actual NE1:04e8 (FILE0ce8). The member's __IOERROR binding does not prove this subordinate is the vendor implementation. Its effects and a modern error/I/O API remain unproved.");
        c.label(0xce8, "scrantic_lseek_subordinate_04e8");
        c.comment(0xce8, "Actual near target of the qualified LSEEK member. This profile marks the binding only, not a complete subordinate function or vendor __IOERROR equivalence.");

        monitor.checkCancelled();
        c.function(0x2eb8, 0x2f01, "scrantic_cwm31_fheap_farmallocf_correspondence", 0, "NE1:[26b8,2701), complete73-byte/33-instruction bound correspondence to FHEAP public __farmallocf. Three DS-relative WORD operands bind0027; the FAR field26e3 binds actual NE13:07e5. Vendor __WinAllocFlag/__GETMEM are laboratory binding roles, not historical names or a proved allocation ABI. BP-based SP restoration and terminal plain RETF establish zero own argument purge; subordinate register/memory/allocator semantics remain unproved.");
        c.label(0x2eb8, "scrantic_cwm31_fheap_farmallocf_correspondence");
        c.function(0x2f76, 0x2faa, "scrantic_cwm31_fheap_farfreef_correspondence", 0, "NE1:[2776,27aa), complete52-byte/25-instruction bound correspondence to FHEAP public __farfreef. Three DS-relative WORD operands bind0027; FAR field2798 binds actual NE13:0962. Vendor __WinAllocFlag/__RLSMEM are laboratory binding roles, not original names or proved release semantics. BP-based SP restoration and terminal plain RETF establish zero own argument purge; subordinate effects and ABI remain unproved.");
        c.label(0x2f76, "scrantic_cwm31_fheap_farfreef_correspondence");
        c.farReference(0x2ee3, 13, 0x07e5, 0x179e5);
        c.label(0x2ee3, "scrantic_fheap_getmem_binding");
        c.comment(0x2ee3, "Original NE1:26e3 singleton/nonadditive type3 width4 flags0 relocation -> NE13:07e5; native relocated pair is required, not raw FFFF:0000. Member __GETMEM binding does not establish allocator equivalence; the surrounding original provider differs from the inspected vendor allocator.");
        c.farReference(0x2f98, 13, 0x0962, 0x17b62);
        c.label(0x2f98, "scrantic_fheap_rlsmem_binding");
        c.comment(0x2f98, "Original NE1:2798 singleton/nonadditive type3 width4 flags0 relocation -> NE13:0962. Member __RLSMEM binding is established; release semantics, preservation and complete provider equivalence are not.");
        c.label(0x179e5, "scrantic_fheap_subordinate_13_07e5");
        c.comment(0x179e5, "Actual original target of the FHEAP73 binding; label only. Whole allocator/vendor equivalence is not established, and the known vendor predicate difference must not be normalized away. No transitive allocation contract is installed.");
        c.label(0x17b62, "scrantic_fheap_subordinate_13_0962");
        c.comment(0x17b62, "Actual original target of the FHEAP52 binding; label only, not a complete release-function or imported ABI claim.");
        c.label(0x17e27, "scrantic_fheap_dgroup_0027_binding");
        c.comment(0x17e27, "Original NE14/DGROUP offset0027 supplies the six WORD displacement bindings in the selected FHEAP bodies. Vendor __WinAllocFlag is a binding role only; runtime DS identity, selector validity, lifetime and global meaning remain unproved.");

        monitor.checkCancelled();
        int unknown = Function.UNKNOWN_STACK_DEPTH_CHANGE;
        c.function(0x2a9c, 0x2aae, "scrantic_cwm31_heap_malloc_correspondence", unknown, "NE1:[229c,22ae), complete18-byte bound HEAP member/public _malloc correspondence. Pushes literal zero and incoming BP+6, then imported KERNEL ordinal5. Terminal RETF has no immediate; imported cleanup/effects and net cleanup are unproved, so native cleanup remains UNKNOWN. No modern malloc prototype, pointer or allocation semantics.");
        c.label(0x2a9c, "scrantic_cwm31_heap_malloc_correspondence");
        c.function(0x2aae, 0x2ae1, "scrantic_cwm31_heap_realloc_correspondence", unknown, "NE1:[22ae,22e1), complete51-byte/29-instruction bound HEAP member/public _realloc correspondence, original raw-caller-qualified rather than newly proved executable ingress. Actual near calls22be->229c and22cb->22f8 are retained. The latter reaches original15, NOT matching vendor FREE20; full/transitive HEAP equivalence is false. Other arm forwards AX/DX/literal2 to KERNEL ordinal6. Import cleanup/effects, unrestricted C/source and modern realloc ABI remain unproved; terminal plain RETF is not a net-cleanup proof.");
        c.label(0x2aae, "scrantic_cwm31_heap_realloc_correspondence");
        c.function(0x2ae1, 0x2af8, "scrantic_cwm31_heap_calloc_correspondence", unknown, "NE1:[22e1,22f8), complete23-byte/12-instruction bound HEAP member/public _calloc correspondence. Pushes0040, computes signed DX:AX product of two incoming WORDs, forwards current low AX to KERNEL ordinal5. No unrestricted product, pointer, allocation or modern calloc ABI interpretation; imported cleanup/effects and net cleanup remain UNKNOWN despite terminal plain RETF.");
        c.label(0x2ae1, "scrantic_cwm31_heap_calloc_correspondence");
        c.function(0x2af8, 0x2b07, "scrantic_original_22f8_not_heap_free20", unknown, "NEGATIVE vendor qualification: original NE1:[22f8,2307) is15 bytes/eight instructions, not genuine HEAP _free20. Original pushes BP+6 directly and unconditionally calls22ff; vendor20 adds a zero test and has different call/return positions. Same KERNEL ordinal7 does not repair correspondence. This original extent ends at terminal2306 RETF; raw00 at2307 and next prefix2308 are excluded. Import effects/cleanup and modern free semantics remain unproved.");
        c.label(0x2af8, "scrantic_original_22f8_not_heap_free20");
        c.comment(0x2abe, "Original NE1:22be near CALL229c, real selected HEAP18 supplier; no relocation overlay or unresolved placeholder.");
        c.comment(0x2acb, "Original NE1:22cb near CALL22f8 after NOP/PUSH CS. This actual target is the15-byte original, not vendor FREE20: matching51-byte wrapper does not prove transitive supplier equivalence.");
        importedBinding(c, 0x2aa7, "scrantic_heap_malloc_kernel5_binding", 5);
        importedBinding(c, 0x2ada, "scrantic_heap_realloc_kernel6_binding", 6);
        importedBinding(c, 0x2af1, "scrantic_heap_calloc_kernel5_binding", 5);
        importedBinding(c, 0x2b00, "scrantic_original_22f8_kernel7_binding", 7);
        log.appendMsg(ID, "Applied exact SCRANTIC LSEEK/FHEAP/HEAP member correspondences and original FREE20 negative; no generic signatures, historical naming, modern prototypes or transitive I/O/heap semantics.");
    }

    private void importedBinding(Context c, long field, String label, int ordinal) throws Exception {
        c.label(field, label);
        c.comment(field, "Original singleton/nonadditive NE type3 width4 flags1 imported operand; module index3 KERNEL ordinal" + ordinal + ". Original FFFF0000 is the source-chain terminator plus placeholder, NOT a callee address. Native loader external-thunk binding is analysis indirection, not the loaded imported implementation or runtime selector. This profile annotates the established ordinal but does not fabricate a target/reference, imported effects, cleanup or API prototype.");
    }
}
