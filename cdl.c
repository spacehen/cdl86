/* cdl (Compact Detour Library) - cdl.c
 *
 * Experimental Linux x86_64 detour library.
 *
 * Copyright (c) 2022 spacehen (Dylan Muller)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "cdl.h"

static int cdl_swbp_alloc();
static uint8_t *str_to_char(const int8_t *str);
static uint8_t *cdl_asm_follow_plt(uint8_t *code);
static int cdl_set_page_protect(uint8_t *code);
static uint8_t *cdl_gen_jmpq_rax(uint8_t *code, uint8_t *rax);
static uint8_t *cdl_gen_nop(uint8_t *code);
static uint8_t *cdl_gen_swbp(uint8_t *code);
static uint8_t *cdl_gen_trampoline(uint8_t *target, uint8_t *bytes_orig,
                                   int size);
static uint8_t *cdl_reserve_bytes(uint8_t *target, int reserve,
                                  int *alloc_size);
static void cdl_nop_fill(uint8_t *target, int size, int patch_size);
static void cdl_swbp_handler(int sig, siginfo_t *info,
                             struct ucontext_t *context);

/* Global variables for state machine. */
int cdl_swbp_size = 0;
bool cdl_swbp_init = false;
struct cdl_swbp_patch *cdl_swbp_hk = 0;

/* Find empty slot in cdl_swbp_hk for new hook and if
 * not present, realloc memory.
 */
int cdl_swbp_alloc()
{
    bool found = false;
    int i = 0;
    int size = sizeof(cdl_swbp_hk[0]);

    /* If cdl_swbp_hk is null, allocate memory. */
    if (!cdl_swbp_hk)
    {
        cdl_swbp_hk = malloc(size);
        cdl_swbp_size++;
        return 0;
    }
    else
    {
        /* Search through struct for inactive member. */
        for (i = 0; i < cdl_swbp_size; i++)
        {
            if (cdl_swbp_hk[i].active == false)
            {
                found = true;
                break;
            }
        }

        /* If we couldn't find inactive member, resize memory. */
        if (!found)
        {
            cdl_swbp_size++;
            cdl_swbp_hk = realloc(cdl_swbp_hk, size * cdl_swbp_size);
            return cdl_swbp_size - 1;
        }
        else
        {
            return i;
        }
    }
}

/* Convert hex string to byte array.
 */
uint8_t *str_to_char(const int8_t *str)
{
    size_t len = strlen(str);
    if (len % 2 != 0)
    {
        return (uint8_t*)NULL;
    }
    size_t flen = len / 2;
    unsigned char *chrs = (unsigned char *)malloc((flen + 1) * sizeof(*chrs));
    for (size_t i = 0, j = 0; j < flen; i += 2, j++)
        chrs[j] = (str[i] % 32 + 9) % 25 * 16 + (str[i + 1] % 32 + 9) % 25;
    chrs[flen] = '\0';
    return chrs;
}

/* Determine info for instruction pointed to by
 * code. Return cdl_ins_probe struct.
 */
struct cdl_ins_probe cdl_asm_probe(uint8_t *code)
{
    int offset = 0x1;
    int size = 0x0;
    bool valid = false;
    struct cdl_ins_probe probe;
    ud_t ud;

    /* Initialize disassembly engine. */
    ud_init(&ud);
    ud_set_mode(&ud, 64);
    /* Enable Intel asm syntax */
    ud_set_syntax(&ud, UD_SYN_INTEL);

    /* Increase window probe size until size!=offset. */
    while (1)
    {
        ud_set_input_buffer(&ud, code, offset);
        size = ud_disassemble(&ud);
        if (size != offset)
        {
            break;
        }
        offset++;
    }
    /* At this point we have finished parsing the first
     * instruction. Disassemble instruction again now that
     * we know instruction size.
     */
    ud_set_input_buffer(&ud, code, size);
    ud_disassemble(&ud);
    probe.disas = (uint8_t *)ud_insn_asm(&ud);
    if (strcmp("invalid", probe.disas))
    {
        valid = true;
    }

    /* Populate probe */
    probe.valid = valid;
    probe.size = size;
    probe.bytes = str_to_char(ud_insn_hex(&ud));
    return probe;
}

/* Determine origin address for possible PLT entry.
 * Return NULL if no PLT entry.
 */
uint8_t *cdl_asm_follow_plt(uint8_t *code)
{
    int rip_offset = 0x0;
    int mnemonic = 0x0;
    uint64_t *got_plt = NULL;
    bool is_plt = false;
    const ud_operand_t *jmp_operand = NULL;
    ud_t ud;

    ud_init(&ud);
    ud_set_mode(&ud, 64);
    ud_set_syntax(&ud, UD_SYN_INTEL);

    /* Strategy for determining whether the target function
     * is associated with a PLT entry is to dissasemble the
     * first BYTES_RESERVE_MAX bytes and check for any JMP
     * mnemonic/instruction within these bytes.
     */
    ud_set_input_buffer(&ud, code, BYTES_RESERVE_MAX);
    while (ud_disassemble(&ud))
    {
        rip_offset += ud_insn_len(&ud);
        mnemonic = ud_insn_mnemonic(&ud);
        /* Check if mnemonic = JMP */
        if (mnemonic == UD_Ijmp)
        {
            /* If a match is found, retreive operand
             * 0 (immediate).
             */
            jmp_operand = ud_insn_opr(&ud, 0);
            is_plt = true;
            break;
        }
    }
    if (!is_plt)
    {
        return (uint8_t*)NULL;
    }

    /* Now trace PLT GOT entry to actual address in memory. */
    got_plt = (uint64_t *)(code + rip_offset + jmp_operand->lval.udword);
    return (uint8_t *)*got_plt;
}

/* Set R/W memory protections for code page. */
int cdl_set_page_protect(uint8_t *code)
{
    int perms = 0x0;
    int ret = 0x0;

    /* Read, write and execute perms. */
    perms = PROT_EXEC | PROT_READ | PROT_WRITE;
    /* Calculate page size */
    uintptr_t page_size = sysconf(_SC_PAGE_SIZE);
    ret = mprotect(code - ((uintptr_t)(code) % page_size), page_size, perms);

    return ret;
}

/* Generate 'jmpq *%rax' instruction. */
uint8_t *cdl_gen_jmpq_rax(uint8_t *code, uint8_t *rax)
{
    *(code + 0x0) = 0x48;
    *(code + 0x1) = 0xB8;
    *(uint64_t *)(code + 0x2) = (uint64_t)rax;
    *(code + 0xA) = 0xFF;
    *(code + 0xB) = 0xE0;
    return code;
}

/* Generate nop instruction. */
uint8_t *cdl_gen_nop(uint8_t *code)
{
    *(code + 0x0) = 0x90;
    return code;
}

/* Generate int3 instruction. */
uint8_t *cdl_gen_swbp(uint8_t *code)
{
    *(code + 0x0) = 0xCC;
    return code;
}

/* Trampoline generation logic. Given a
 * target address, instruction byte array and size
 * return address of generated trampoline function.
 */
uint8_t *cdl_gen_trampoline(uint8_t *target, uint8_t *bytes_orig, int size)
{
    uint8_t *trampoline;
    int prot = 0x0;
    int flags = 0x0;

    /* New function should have read, write and
     * execute permissions.
     */
    prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    flags = MAP_PRIVATE | MAP_ANONYMOUS;

    /* We use mmap to allocate trampoline memory pool. */
    trampoline = mmap(NULL, size + BYTES_JMP_PATCH, prot, flags, -1, 0);
    memcpy(trampoline, bytes_orig, size);
    /* Generate jump to address just after call
     * to detour in trampoline. */
    cdl_gen_jmpq_rax(trampoline + size, target + size);

    return trampoline;
}

/* Reserve bytes at address of target. Calculates
 * minimum number of bytes required to fully replace
 * instructions at target address by size 'reserve'.
 */
uint8_t *cdl_reserve_bytes(uint8_t *target, int reserve, int *alloc_size)
{
    int bytes = 0x0;
    uint8_t *bytes_orig = NULL;
    struct cdl_ins_probe probe;

    /* Ensure we can't reserve more than
     * BYTES_RESERVE_MAX.
     */
    if (reserve > BYTES_RESERVE_MAX)
    {
        return (uint8_t*)NULL;
    }
    /* Allocate buffer to hold original instruction
     * bytes.
     */
    bytes_orig = malloc(BYTES_RESERVE_MAX);
    /* Prove instructions until bytes > reserve. */
    while (bytes < reserve)
    {
        probe = cdl_asm_probe(target + bytes);
        memcpy(bytes_orig + bytes, probe.bytes, probe.size);
        bytes += probe.size;
        free(probe.bytes);
    };

    *alloc_size = bytes;
    /* Return original instruction bytes.
     * buffer
     */
    return bytes_orig;
}

/* Fill unpatched bytes with NOPs to
 * avoid segfault.
 */
void cdl_nop_fill(uint8_t *target, int size, int patch_size)
{
    int nops = 0x0;

    nops = size - patch_size;
    while (nops-- > 0)
    {
        cdl_gen_nop(target + patch_size + nops);
    }
    return;
}

/* Software breakpoint handler. Handles incomming
 * SIGTRAP signal once INT3 breakpoint is hit.
 *
 * The handler functions by comparing the value
 * of the RIP-0x1 register as provided by the ucontext_t
 * struct of the signal to the active breakpoint addresses
 * (bp_addr).
 *
 * If a match is found then the RIP register of the current
 * context if updated to the address of the detour function.
 */
void cdl_swbp_handler(int sig, siginfo_t *info, struct ucontext_t *context)
{
    int i = 0x0;
    bool active = false;
    uint8_t *bp_addr = NULL;

    /* RIP register point to instruction after the
     * int3 breakpoint so we subtract 0x1.
     */
    bp_addr = (uint8_t *)(context->uc_mcontext.gregs[REG_RIP] - 0x1);

    /* Iterate over all breakpoint structs. */
    for (i = 0; i < cdl_swbp_size; i++)
    {
        active = cdl_swbp_hk[i].active;
        /* Compare breakpoint addresses. */
        if (bp_addr == cdl_swbp_hk[i].bp_addr)
        {
            /* Update RIP and reset context. */
            context->uc_mcontext.gregs[REG_RIP] = (greg_t)cdl_swbp_hk[i].detour;
            setcontext(context);
        }
    }
}

/* Patches function pointed to by 'target' with
 * a JMP to the detour function. *target is then
 * updated to point to the newly allocated trampoline.
 */
struct cdl_jmp_patch cdl_jmp_attach(void **target, void *detour)
{
    int bytes = 0x0;
    int i = 0x0;
    int nops = 0x0;
    uint8_t *trampoline = NULL;
    uint8_t *target_origin = NULL;
    uint8_t *plt_got = NULL;
    uint8_t *bytes_orig = NULL;
    struct cdl_jmp_patch jmp_patch = {};

    target_origin = *target;
    /* Check if target pointer is PLT entry. */
    plt_got = cdl_asm_follow_plt(target_origin);
    /* If PLT.GOT entry found, update origin. */
    if (plt_got)
    {
        target_origin = plt_got;
    }
    jmp_patch.target = (uint8_t **)target;

    /* Reserve BYTES_JMP_PATCH bytes for incoming
     * patch.
     */
    bytes_orig = cdl_reserve_bytes(target_origin, BYTES_JMP_PATCH, &bytes);
    jmp_patch.code = bytes_orig;
    jmp_patch.nt_alloc = bytes;

    /* Generate trampoline stub */
    trampoline = cdl_gen_trampoline(target_origin, bytes_orig, bytes);
    jmp_patch.trampoline = trampoline;

    /* Set memory permissions. */
    cdl_set_page_protect(target_origin);
    /* Generate JMP to detour function. */
    cdl_gen_jmpq_rax(target_origin, detour);
    /* Fill remaining bytes with NOPs. */
    cdl_nop_fill(target_origin, bytes, BYTES_JMP_PATCH);

    jmp_patch.origin = target_origin;
    /* Set *target to newly allocated trampoline. */
    *target = trampoline;

    /* Mark patch as active. */
    jmp_patch.active = true;
    return jmp_patch;
}

/* Detach JMP patch and free memory. */
void cdl_jmp_detach(struct cdl_jmp_patch *jmp_patch)
{
    uint8_t *origin = jmp_patch->origin;
    uint8_t *code = jmp_patch->code;
    int nt_alloc = jmp_patch->nt_alloc;

    /* If JMP patch is active, free memory. */
    if (jmp_patch->active)
    {
        memcpy(origin, code, nt_alloc);
        /* Unmap trampoline. */
        munmap(jmp_patch->trampoline, nt_alloc + BYTES_JMP_PATCH);
        *jmp_patch->target = jmp_patch->origin;
        free(jmp_patch->code);

        /* Set jmp_patch memory to 0. */
        memset(jmp_patch, 0, sizeof(*jmp_patch));
    }
    return;
}

/* Patches function pointed to by 'target' with
 * a INT3 BP to the detour function. *target is then
 * updated to point to the newly allocated stub.
 */
struct cdl_swbp_patch cdl_swbp_attach(void **target, void *detour)
{
    int bytes = 0x0;
    int id = 0x0;
    int size = 0x0;
    uint8_t *stub = NULL;
    uint8_t *bytes_orig = NULL;
    uint8_t *target_origin = NULL;
    uint8_t *plt_got = NULL;
    struct cdl_swbp_patch swbp_patch = {};
    struct sigaction sa = {};

    /* Initialise cdl signal handler. */
    if (!cdl_swbp_init)
    {
        /* Request signal context info which
         * is required for RIP register comparison.
         */
        sa.sa_flags = SA_SIGINFO | SA_ONESHOT;
        sa.sa_sigaction = (void *)cdl_swbp_handler;
        sigaction(SIGTRAP, &sa, NULL);
        cdl_swbp_init = true;
    }

    target_origin = *target;
    /* Check if target pointer is PLT entry. */
    plt_got = cdl_asm_follow_plt(target_origin);
    if (plt_got)
    {
        /* If PLT.GOT entry found, update origin. */
        target_origin = plt_got;
    }
    swbp_patch.target = (uint8_t **)target;
    swbp_patch.detour = detour;

    /* Reserve bytes for INT3 patch. */
    bytes_orig = cdl_reserve_bytes(target_origin, BYTES_SWBP_PATCH, &bytes);
    swbp_patch.code = bytes_orig;
    swbp_patch.ns_alloc = bytes;

    /* Generate stub function. */
    stub = cdl_gen_trampoline(target_origin, bytes_orig, bytes);
    swbp_patch.stub = stub;

    /* Set memory permissions and generate INT3. */
    cdl_set_page_protect(target_origin);
    cdl_gen_swbp(target_origin);

    /* Fill remaining bytes with NOPs. */
    cdl_nop_fill(target_origin, bytes, BYTES_SWBP_PATCH);

    /* Allocate new SW BP id. */
    id = cdl_swbp_alloc();
    swbp_patch.gid = id;
    size = sizeof(swbp_patch);

    swbp_patch.bp_addr = target_origin;
    *target = stub;

    swbp_patch.active = true;
    /* Copy struct data to global SWBP variable
     * (cdl_swbp_hk).
     */
    memcpy(cdl_swbp_hk + (size * id), &swbp_patch, size);

    return swbp_patch;
}

/* Detach INT3 patch and free memory. */
void cdl_swbp_detach(struct cdl_swbp_patch *swbp_patch)
{
    uint8_t *bp_addr = swbp_patch->bp_addr;
    uint8_t *stub = swbp_patch->stub;
    uint8_t *code = swbp_patch->code;
    int ns_alloc = swbp_patch->ns_alloc;

    /* If JMP patch is active, free memory. */
    if (swbp_patch->active)
    {
        memcpy(bp_addr, code, ns_alloc);
        /* Unmap strub function. */
        munmap(swbp_patch->stub, ns_alloc + BYTES_JMP_PATCH);
        *swbp_patch->target = swbp_patch->bp_addr;
        free(code);

        /* Set global SWBP active status for gid to
         * flase.
         */
        cdl_swbp_hk[swbp_patch->gid].active = false;
        memset(swbp_patch, 0, sizeof(*swbp_patch));
    }
    return;
}

/* Print debug info for JMP patch. */
void cdl_jmp_dbg(struct cdl_jmp_patch *jmp_patch)
{
    printf("origin      : 0x%" PRIx64 "\n", (uint64_t)jmp_patch->origin);
    printf("trampoline  : 0x%" PRIx64 "\n", (uint64_t)jmp_patch->trampoline);
    printf("nt_alloc    : %i\n", jmp_patch->nt_alloc);
    printf("active      : 0x%" PRIx64 "\n", (uint64_t)jmp_patch->active);
}

/* Print debug info for INT3 patch. */
void cdl_swbp_dbg(struct cdl_swbp_patch *swbp_patch)
{
    printf("bp_addr   : 0x%" PRIx64 "\n", (uint64_t)swbp_patch->bp_addr);
    printf("stub      : 0x%" PRIx64 "\n", (uint64_t)swbp_patch->stub);
    printf("ns_alloc  : %i\n", swbp_patch->ns_alloc);
    printf("gid       : %i\n", swbp_patch->gid);
    printf("active    : 0x%" PRIx64 "\n", (uint64_t)swbp_patch->active);
}
