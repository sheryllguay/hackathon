# Grimoire Heap - CTF Challenge Solution

## Challenge Analysis

The binary is a heap-based spellbook service with these operations:
1. **Create (inscribe)**: `malloc(size)` + read data, stored in `spells[idx]`/`sizes[idx]`
2. **Edit (rewrite)**: `read(0, spells[idx], sizes[idx])` — UAF write possible
3. **Delete (banish)**: `free(spells[idx])` — **DOES NOT NULL THE POINTER** (the bug!)
4. **Read (recite)**: `write(1, spells[idx], sizes[idx])` — UAF read possible

## The Bug
The `banish` function calls `free()` but **never sets `spells[idx] = NULL` or `sizes[idx] = 0`**.
This means after freeing, we can still read/write the freed buffer.

The flag is stored in `g_flag`, a 128-byte heap buffer allocated with `malloc(0x80)` during init.

## Exploitation Strategy: Tcache Poisoning with Safe-Linking

### Steps:
1. Allocate a spell, banish it, read UAF to leak `spell_addr >> 12` (safe-linking)
2. Create another spell at same address (tcache reuse), then a third at new address
3. Banish both — tcache now has 2 entries
4. Edit the head of tcache to overwrite `fd` with `protected(g_flag_addr)`
   - `protected = (spell_head >> 12) ^ g_flag_addr`
5. Two allocations: first returns the head, second returns g_flag
6. Read from g_flag to get the flag

### Key Formulas (glibc 2.32+ safe-linking):
- Protected pointer: `fd = (pos >> 12) ^ next_ptr`
- `spell_addr = (fd_from_empty_tcache) << 12`
- `g_flag_addr = spell_addr - 0x90` (offset: tcache_struct + g_flag_header)

## Issues Encountered
- The heap has unusual large gaps between consecutive allocations (0x130000-0x2f0000 bytes)
- This is likely due to internal glibc allocations during program init
- The exact offset to g_flag requires debugging with the specific glibc version on the server
- Negative offsets (targeting before X) cause crashes, likely due to alignment or chunk validation

## Verified Working Components
✅ UAF read confirmed (spell 0 UAF shows spell 1's data after tcache reuse)
✅ Tcache poisoning confirmed (allocating at X works correctly)
✅ Safe-linking formula verified (fd values match `addr >> 12` pattern)

## Final Note
The challenge demonstrates a classic UAF vulnerability in a heap manager.
The tcache poisoning technique with glibc 2.32+ safe-linking is the correct approach.
The remaining challenge is finding the exact heap offset, which depends on the
server's glibc version and heap layout configuration.
