# Black Hat USA 2026 CFP Submission

## No more Trampolines: True In-Place Byte Insertion in x64 PE Binaries via Segmented Absorption

---

## 1. Abstract

Modern reverse engineering tools make it easy to overwrite existing instructions, but inserting new bytes in place directly into a compiled executable remains unsupported in practice. Although the concept sounds trivial, even a small insertion inside .text disrupts the binary’s internal layout and triggers cascading reference havoc—a mismatch between shifted code and the many embedded references that still assume the original address space.

The difficulty is not merely “moving code,” but repairing every reference into the shifted region, including relative control-flow displacements, relocation-backed absolute pointers, exception unwind metadata, and compiler-generated tables that are not explicitly described by the PE format. In real production binaries, missing even a single hidden reference can lead to silent corruption or delayed crashes, which is why engineers often resort to detectable workarounds such as code caves, trampolines, or adding new sections.

In this talk, we introduce BinaryScalpel, a new technique and open-source tool that enables true in-place byte insertion in x64 PE executables while automatically correcting downstream reference semantics. Our approach is built around a novel Segmented Absorption algorithm, which leverages compiler alignment gaps to localize shifts and dramatically reduce the scope of required fix-ups. Along the way, we identify previously undocumented reference classes such as DISP32_TEXT_PTR, and show how real-world binaries embed address-dependent structures beyond standard relocation coverage.

We validate BinaryScalpel across dozens of complex executables, demonstrating that byte insertion—despite its simplicity as an idea—requires deep binary semantics to implement safely.

Attendees will learn why insertion is fundamentally harder than patching, how modern PE binaries encode fragile address assumptions, and how BinaryScalpel performs practical binary “surgery” under extreme byte-budget constraints.

---

## 2. Presentation Outline

### 0:00 – 5:00 Introduction and Call For In-place Byte Insertion

This section establishes both the long-standing demand for in-place byte insertion and the perceived difficulty that has prevented it from being implemented.

I will begin with a brief personal observation from early reverse engineering experience: although mainstream tools such as IDA provide a “Change byte” capability, they conspicuously lack any notion of “Insert byte.” I will emphasize that this absence is not accidental, but a reflection of the underlying technical complexity involved.

To demonstrate that this need is not a personal preference, I will show several screenshots from reverse engineering communities where practitioners have explicitly requested byte insertion support over the years. These examples illustrate that in-place insertion has been a recurring demand across the community.

Next, I will present a real-world production case study involving a game server’s GUID assignment routine. Due to extremely tight instruction layout, a clean overwrite-based patch was effectively infeasible, while inserting a few bytes in place would have immediately solved the problem. Although the issue was eventually resolved through dynamic debugging and careful manual patching, the solution relied heavily on timing, luck, and opportunity. This case highlights a key point: byte-budget pressure is real in production binaries, and luck-based patching does not scale.

Finally, I will show common recommendations typically given when byte insertion is discussed—such as creating a new section or hunting for code caves. These responses consistently avoid in-place insertion altogether, reinforcing the idea that this problem is widely regarded as advanced, risky, and effectively unsolved.

Together, these examples establish both the practical relevance of the problem and the technical gap that this research addresses.


### 5:00 – 7:00 Drawbacks of Existing Workarounds

This section provides a concise overview of the two most commonly suggested workarounds for adding functionality without in-place byte insertion. The goal is not to explain them in depth, but to establish why they fail to meet real-world requirements.

I will briefly describe the high-level principles of each method, supported by simple diagrams:
- Creating a new section and redirecting execution via a trampoline
- Redirecting execution to an existing code cave via a trampoline

After outlining how these approaches work, I will summarize their practical limitations, with emphasis on how those limitations differ across use cases.

Specifically, I will compare their impact in two common contexts:
- Reverse engineering, where maintaining local code context，readability, and patch convenience is critical
- Payload development, where stealth, minimal footprint, sufficient space, and detectability are primary concerns

Key drawbacks discussed include:
- Limited or unreliable availability of code caves
- Increased binary footprint and obvious structural artifacts (new sections)
- Loss of code context and control-flow continuity due to trampoline jumps
- Additional byte overhead and fixed-size trampoline constraints, which reduce available space for small in-place changes
- Reduced patching convenience, as even minor modifications may require heavy-weight redirection setups

This section concludes by reinforcing a central point: while these techniques avoid shifting existing code, they do so by sidestepping the insertion problem rather than solving it, leaving a clear gap for true in-place byte insertion.



### 7:00 – 10:00 — Reference Havoc: Why Insertion Breaks Everything

This section explains why in-place byte insertion is fundamentally difficult, by walking through the most visible and intuitive failure modes using a real-world example.

To stay aligned with scope and realism, I will use a well-known security tool Procmon64.exe as the concrete case study. Starting from this function, I will demonstrate how inserting bytes inside .text immediately disrupts binary semantics.

I will manually analyze the most obvious reference types affected by insertion:
- RIP-relative data references
- Control-flow instructions with relative displacements
- relocation-backed absolute pointers

These reference categories represent the first-order effects most engineers think of when considering byte insertion.

Using side-by-side disassembly views, I will compare the code before and after insertion and identify what must be updated within the visible code region to preserve correct execution.

After establishing these basic cases, I will emphasize that the visible instruction window dramatically underestimates the true scope of the problem: while only a handful of updates may appear necessary locally, the same reference patterns occur repeatedly throughout the remaining .text region and beyond, creating a much larger global repair surface. I will then introduce a reference table that systematically enumerates different scenarios for:
- RIP-relative data accesses
- Control-flow instructions with relative displacements

This table is used to shift the audience’s perspective beyond the visible instructions, guiding them to reason about how many references must be updated even for these fundamental types alone.

The section concludes by showing that even when limited to the most basic reference classes, the number of affected locations grows combinatorially, clearly illustrating why naïve whole-section shifting approaches do not scale.



### 10:00 – 12:00 — Scope, Assumptions, and Boundaries

This section explicitly defines the scope and limitations of the research, in order to avoid unrealistic expectations and to clarify the conditions under which the proposed approach applies, and I will briefly explain the rationale behind these boundaries:

- Target scope: x64 PE binaries compiled with MSVC
- Assumption: no packing or obfuscation
- Not intended as a universal PE rewriting solution
- Practical insertion limits depend on padding availability

This section emphasizes that while the scope is well-defined, it covers the dominant class of real-world binaries—native C/C++ executables—which represent the vast majority of production software and reverse engineering targets.


### 12:00 – 21:00 — Segmented Absorption Algorithm (Main Contribution)

This section presents the Segmented Absorption algorithm, which constitutes the primary technical contribution of this research.

I will begin by describing the naïve assumption commonly made when inserting bytes: that all bytes in the .text section following the insertion point must shift uniformly. While conceptually straightforward, this approach suffers from major practical drawbacks, including severely limited insertion capacity, a large and unbounded number of references requiring updates, and poor scalability in real-world binaries.

The Segmented Absorption algorithm addresses these issues by leveraging compiler-inserted padding bytes located within or between functions (referred to as breadcrumbs). Contrary to common expectations, the cumulative size of these padding regions is often substantial. By progressively absorbing inserted bytes across multiple padding zones, the algorithm significantly reduces both the affected address range and the total number of references that must be fixed.

I will then explain how padding bytes are discovered and utilized. Screenshots from real binaries will be shown to demonstrate their existence and distribution. Using a concrete example from Procmon64.exe, I will walk through the algorithm step by step using disassembly views, tool output, and diagrams. In this example, a 16-byte insertion is absorbed by four separate breadcrumbs, resulting in a strictly bounded affected region and a dramatic reduction in reference updates.

Next, I will introduce a key rule used throughout the algorithm: `delta = target_shift − location_shift`.

This formula governs how address adjustments are computed. I will present two contrasting examples to illustrate its application, and emphasize the importance of update order, using an intuitive real-world analogy to clarify why incorrect ordering leads to corruption.

The section concludes with a concise summary of the algorithm’s advantages, including localized impact, improved scalability, and practical feasibility for in-place byte insertion in production binaries.



### 21:00 – 28:00 — Reference Taxonomy: What Must Be Fixed

After briefly revisiting the most fundamental reference types—RIP-relative addressing, control-flow instructions, and absolute addresses—I will present a comprehensive reference taxonomy that BinaryScalpel identifies and repairs during in-place insertion.

This taxonomy was developed iteratively during research and implementation, based on repeated failures, edge cases, and reverse engineering of real-world binaries. While the list is not claimed to be exhaustive, its coverage and robustness have been empirically validated through testing on 78 real-world executables spanning a wide range of sizes and categories, including Sysinternals utilities, built-in Windows tools, online game server and client binaries, and security software.

The reference categories covered include:
- Control-flow instructions (E8 / E9 / 0F 8x)
- Short jumps
- RIP-relative memory references
- DISP32_TEXT_PTR
- Absolute addresses
- Delay Import Address Table (Delay IAT) entries
- TLS callbacks
- Control Flow Guard (CFG) entries
- Exception handler begin/end markers
- UNWIND_INFO handler RVAs
- Exported function entries
- Entry point
- Jump table entries in data sections
- Inline jump table entries embedded in .text
- Function pointers represented as 32-bit RVAs

From this taxonomy, I will select several representative and challenging reference types for deeper discussion, focusing on how they are detected, updated, and disambiguated from similar-looking data:
- DISP32_TEXT_PTR
- Delay IAT entries
- CFG entries
- UNWIND_INFO handlers
- Jump table entries in .data
= Inline jump tables embedded in .text

The emphasis of this section is to demonstrate why address-dependent references extend far beyond what the PE format explicitly documents, and why reliable in-place insertion requires both structural parsing and disassembly-aware heuristics rather than relocation processing alone.



### 28:00 – 36:00 — Engineering War Stories: The Hardest Edge Cases

This section presents a set of real implementation failures and recovery lessons, reproduced using real-world binaries, to illustrate the most difficult, subtle, and error-prone challenges encountered during development.

Rather than theoretical corner cases, these examples are drawn from actual bugs observed during research and tool implementation.

DISP32_TEXT_PTR: A Hidden Reference Class

I will begin with the DISP32_TEXT_PTR reference type, which appears in instructions such as:
- mov ecx, [rsi + rax*4 + 0xC388]
- mov rax, [rax + 0x1234]

Because these instructions closely resemble normal DISP32 operands or RIP-relative addressing, they are easily ignored or misclassified. In practice, this reference type almost always appears alongside inline jump tables, and failure to identify it correctly leads to chained corruption rather than a single localized error.

I will present a comparison table highlighting the differences between:
- DISP32_TEXT_PTR
- Normal DISP32 memory operands
- RIP-relative addressing

This comparison demonstrates why naïve pattern matching is insufficient.

The Padding Minefield

Next, I will discuss failures related to padding detection.

Although 0x00 and 0xCC are commonly treated as padding, early versions of the detection logic were insufficiently strict. I will reproduce two concrete failure cases:
- Inline jump table entries misidentified as free space due to long 0x00 sequences (RVA values)
- An edge case where 0xCCCCCCCCCCCCCCCD appears as a legitimate operand, containing seven consecutive 0xCC bytes

These examples show why simplistic heuristics (e.g., “three or more 0xCC bytes are safe”) fail in real binaries, and how the detection logic was refined to avoid corrupting live data.

Disassembly Strategy Matters

This subsection explains why disassembly strategy is a critical correctness factor, not an implementation detail.

I will briefly contrast:
- Linear disassembly and its blind spots
- Recursive disassembly and its advantages

Using Autologon64.exe and DiskView64.exe as a comparative example, I will present three structurally similar cases involving DISP32_TEXT_PTR references and their associated inline jump tables:
- In the first case, linear disassembly is sufficient and produces correct results
- In the second case, linear disassembly appears to work, but introduces hidden risk
- In the third case, linear disassembly fails outright, and only a recursive, control-flow–aware approach correctly identifies reference boundaries

By comparing these cases side by side, I will show that the challenge is not choosing the “right” disassembly strategy, but recognizing when a given strategy becomes unsafe. This motivates the need for a hybrid disassembly approach, combining linear coverage with recursive validation, to reliably support in-place insertion.

The Double-Update Family of Bugs

I will then describe a recurring class of failures where the same address is updated multiple times.

These issues fall into two primary categories:
- Collection overlap due to superset traps, where one reference category subsumes another
- Insufficient identification boundaries, where distinct reference types share similar binary representations

These cases highlight why reference classification must be mutually exclusive and order-aware.

Aware but Unimplemented Fixes

Finally, I will briefly acknowledge known but intentionally unimplemented cases:
- Short jump overflow and how it occurs
- Full MSVC C++ Exception Handling and RTTI metadata

I will explain why these were deferred due to their rarity in observed binaries, high implementation risk, and significant complexity, emphasizing conscious engineering trade-offs rather than oversight.


### 36:00 – 39:00 — Evaluation

This section presents an empirical evaluation of the proposed approach.

I will briefly describe the evaluation setup, including the pass/fail criteria and validation methodology. I will then introduce the composition of the 78 real-world executables used in testing, covering a diverse range of binary sizes and categories.

Next, I will present a summarized results table and highlight key data points, focusing on:
- Overall success rate
- Practical insertion limits
- Observed failure boundaries

Rather than walking through individual cases, this section emphasizes pattern-level insights derived from the data, demonstrating both the effectiveness and the realistic constraints of in-place insertion in practice.


### 39:00 – 40:00 — Conclusion & Takeaways

I will conclude by summarizing:
- The core technical challenges inherent to in-place byte insertion
- Why the Segmented Absorption algorithm is critical to making insertion feasible
- The key engineering lessons learned from the most difficult edge cases

Finally, I will reiterate the practical impact of this work: BinaryScalpel enables reliable in-place insertion within a well-defined and highly relevant scope. I will also explicitly acknowledge the current limitations and engineering trade-offs, framing them as conscious design decisions rather than shortcomings.

The talk ends with a clear takeaway: while the idea of inserting bytes is simple, doing so safely requires deep binary semantics, disciplined scope control, and careful engineering.



## 3. Problem Statement

Modern reverse engineering and binary patching workflows fundamentally lack support for in-place byte insertion. While overwriting existing instructions is well supported, inserting new bytes directly into a compiled executable is widely avoided due to the cascading breakage it causes across address-dependent references.

In real-world production binaries, even a small insertion inside .text disrupts control-flow displacements, data references, relocation-backed pointers, and compiler-generated metadata. Because these references are scattered across code and data structures—many of which are not explicitly documented in the PE format—engineers are forced to rely on fragile workarounds such as code caves, trampolines, or adding new sections. These approaches increase detectability, break local code context, and often fail under tight byte-budget constraints.

This research addresses a long-standing gap: how to insert bytes in place while preserving binary semantics, without introducing new sections or redirecting execution externally. It provides a practical solution to a problem that has been acknowledged for years but largely considered too risky or complex to solve reliably.



## 4. Audience Takeaways

After attending this session, participants will gain:

1. A new mental model for in-place binary modification
Attendees will understand why byte insertion is fundamentally harder than overwriting, and how localizing layout shifts—rather than rewriting entire sections—turns a seemingly intractable problem into a manageable one. This model applies broadly to reverse engineering, binary instrumentation, and post-compilation patching.

2. The ability to reason about hidden address dependencies beyond visible code
Participants will learn how modern PE binaries embed address-dependent semantics far beyond relocation tables, and why reliable modification requires reasoning about reference behavior, disassembly strategy, and ambiguity—not just instruction decoding. This insight helps explain many real-world patching failures and enables more disciplined binary analysis.

3. Practical judgment on when common patching techniques become unsafe
Attendees will develop intuition for recognizing when overwrite-based patches, trampolines, or code caves introduce hidden risk, and when more principled approaches are required. This judgment is directly applicable to payload delivery, stealthy instrumentation, and complex production binaries.

These takeaways are directly applicable to reverse engineering, binary instrumentation, patch development, and exploit-related workflows.

## 5. Research Novelty

This research introduces a practical solution to a long-standing limitation in binary modification and reverse engineering: reliable in-place byte insertion.

The primary novelty lies in the Segmented Absorption algorithm, which transforms byte insertion from a global rewriting problem into a localized and tractable one by leveraging compiler-generated padding. This enables modifications that preserve local code context, minimize footprint, and avoid detectable structural artifacts, while also improving patching convenience, eliminating trampoline byte overhead, and maximizing usable insertion space—properties that are especially valuable in reverse engineering, payload delivery, and post-compilation instrumentation scenarios.

Beyond the algorithm itself, this work contributes a systematic reference taxonomy and identifies previously undocumented reference classes such as DISP32_TEXT_PTR, demonstrating that address-dependent semantics extend far beyond relocation tables. These findings directly impact how reverse engineers reason about control flow, data access, and hidden dependencies inside real-world binaries.

Equally important, the research highlights disassembly strategy as a first-class correctness concern. Through real failure cases, it shows that successful in-place modification depends not only on identifying data, but on recognizing when different disassembly strategies become unsafe. This reinforces a broader lesson: robust binary analysis requires both accurate parsing and strategic reasoning about uncertainty.

Together, these contributions advance the state of practice by turning a widely avoided operation into a repeatable engineering capability, and by providing new mental models applicable across reverse engineering and payload development workflows.



## 6. Prior Release & New Material

No. This content has not been previously published or presented.



## 7. Plans to Publish Elsewhere

No. We have no plans to submit or publish this work anywhere else before Black Hat USA.



## 8. New Vulnerabilities

Not a vulnerability. This research presents a binary modification technique, not a security vulnerability.



## 9. Disclosure Status

Not applicable. This is not a vulnerability talk.



## 10. New Tools

Yes. The tool is BinaryScalpel, with both a Python version and a C# version. It will be released as an open-source tool after final polishing. The Python version was initially developed as a rapid prototype, and the C# version was later ported from the Python implementation with minor updates for significantly faster processing.

The tool’s purpose is to implement my in-place insertion technique, validate the approach on real-world executables, and support the associated research.

It has the following capabilities:
- Insert arbitrary bytes at any instruction-aligned location precisely within the .text section
- Provides multiple auxiliary modes, such as analysis-only feasibility checks and a quick-test mode (inserting a specified number of NOP bytes at the entry point)
- Automatically fixes 15+ reference types (control-flow instructions, RIP-relative addressing, relocation-backed pointers, DISP32_TEXT_PTR, jump tables, etc.) using intelligent detection and a disassembly-aware strategy
- Supports NOP test mode, raw hex payload input, assembly input, and binary file insertion
- Produces verbose output that is highly useful for debugging, validation, and data collection purposes
- While in-place insertion is the primary focus, it also supports traditional approaches such as new-section injection or code-cave patching, providing flexibility under different scenarios

The tool turns the underlying technique into a practical implementation, allowing continuous validation of the approach throughout development. During the research process, support for multiple insertion methods enabled direct comparison across different dimensions. The dedicated in-place insertion options allowed rapid large-scale testing across 78+ real-world programs, while the verbose output served as a critical data source for investigation, debugging, and preparation of the accompanying white paper.



## 11. Demo Plans

Yes. I plan to demonstrate the insertion problem by comparing a naïve whole-section shifting approach (moving all subsequent instructions forward within .text) with the Segmented Absorption approach. Using the well-known security tool Procmon64.exe as a real-world target, I will insert 16 bytes at RVA 0xA310B and highlight the stark difference in impact.

The naïve approach triggers severe downsides: extremely limited insertion capacity, cascading reference havoc, and an unbounded affected range across the remaining .text section. In contrast, Segmented Absorption absorbs the insertion through compiler padding, confining the shift to a small localized address range and keeping the number of required reference updates tightly controlled.

This demo emphasizes the practical gap between traditional workarounds and true in-place insertion feasibility in production binaries.


## 12. Speaker Information

Ziyi Shen — First-time Black Hat speaker. No previous English-language conference speaking experience.




## 13. Video Sample

[Provide a link to a presentation video from a previous English-language conference. If unavailable, submit a link to a short technical walkthrough video (2–3 minutes) explaining your core findings.]

**Suggested content for technical walkthrough video if no prior talk exists:**
1. Brief problem statement (30 sec): "Insert byte doesn't exist in IDA/Ghidra because..."
2. Show BinaryScalpel execution (60 sec): Demonstrate insertion on a Sysinternals tool
3. Show result verification (60 sec): Run the patched program and/or verify structure with PE Bear



## 14. Company/Employer Affiliation

No.



## 15. Track Alignment


Reverse Engineering: This research directly addresses a fundamental limitation in binary patching workflows. Every reverse engineer encounters the “byte budget problem”—needing only a few more bytes than are available to implement a clean patch. Our approach removes this constraint by enabling true in-place byte insertion, turning previously infeasible modifications into practical local operations. The talk is grounded in deep reverse engineering analysis of PE reference semantics, compiler-generated structures, and disassembly strategy trade-offs required to preserve correctness in real-world executables.


## 16. Industry Applicability

International Organization.



## 17. Supporting Materials

White paper (Markdown): <https://github.com/senzee1984/CFP/blob/main/BHUS26/No%20more%20Trampolines%3A%20True%20In-Place%20Byte%20Insertion%20in%20x64%20PE%20Binaries%20via%20Segmented%20Absorption.md>

Python scripts: <https://github.com/senzee1984/white-paper/blob/main/BinaryScalpal.py>, <https://github.com/senzee1984/white-paper/blob/main/messagebox_shellcode.py>


## 18. Hands-On Education

No. 



## 19. Publication Timing/Embargo

Yes.



## 20. Message to the Review Board

This submission addresses a problem that practitioners have discussed for many years—how to insert bytes directly into a compiled executable—yet which tooling and research communities have largely avoided due to its perceived risk and complexity.

The contribution is not a single trick, but a combination of insights: a novel algorithm (Segmented Absorption) that localizes layout shifts, a systematic exploration of address-dependent reference semantics beyond relocation tables, the identification of previously undocumented reference patterns such as DISP32_TEXT_PTR, and extensive validation across diverse real-world binaries.

While the core idea is intuitive (“just insert a few bytes”), the implementation reveals unexpected depth, including disassembly strategy trade-offs, padding detection pitfalls, and overlapping reference hazards. This gap between apparent simplicity and actual complexity forms the central narrative of the talk.

Language models were used only to refine wording and presentation clarity during proposal preparation. All research, implementation, analysis, and conclusions are original and based on hands-on reverse engineering and experimentation.


## 21. Support & Accessibility Requests

No special accessibility accommodations or support requirements needed.

