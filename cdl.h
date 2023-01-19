/* cdl86 (Compact Detour Library) - cdl.h
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

#ifndef CDL_H
#define CDL_H

#define _GNU_SOURCE

/* Global includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <signal.h>
#include <ucontext.h>
#include <inttypes.h>

/* Local includes */
#include "lib/udis86.h"

/* Define JMP patch length,
 * see (cdl_gen_jmpq_rax)
 */
#define BYTES_JMP_PATCH 12

/* Define SW BP patch length,
 * see (cdl_gen_swbp)
 */
#define BYTES_SWBP_PATCH 1

/* General : reserve bytes */
#define BYTES_RESERVE_MAX 20

/* Intruction probe struct.
 *
 * size: size of instruction (bytes)
 * valid: is valid instruction (bool)
 * bytes: byte array of instruction (char*)
 * disas: disassembly string (char*)
 */
struct cdl_ins_probe
{
    int size;
    bool valid;
    uint8_t *bytes;
    uint8_t *disas;
};

/* JMP patch info struct.
 *
 * active: is patch active (bool)
 * nt_alloc: number of bytes allocated to trampoline (int)
 * code: instructions replaced by JMP patch (char*)
 * target: pointer to function pointer (char**)
 * origin: pointer to origin(real) target address (char*)
 * trampoline: pointer to trampoline (char*)
 */
struct cdl_jmp_patch
{
    bool active;
    int nt_alloc;
    uint8_t *code;
    uint8_t **target;
    uint8_t *origin;
    uint8_t *trampoline;
};

/* JMP patch info struct.
 *
 * gid: global id for SW BP (int)
 * active: is patch active (bool)
 * ns_alloc: number of bytes allocated to stub (int)
 * code: instructions replaced by SWBP patch (char*)
 * target: pointer to function pointer (char**)
 * stub: pointer to stub (char*)
 * detour: pointer to detour function (char*)
 * bp_addr: address of breakpoint (char*)
 */
struct cdl_swbp_patch
{
    int gid;
    bool active;
    int ns_alloc;
    uint8_t *code;
    uint8_t **target;
    uint8_t *stub;
    uint8_t *detour;
    uint8_t *bp_addr;
};

/* Attach JMP patch to target funciton.
 *
 * target: pointer to function pointer to
 * function to hook.
 * detour: function pointer to detour function
 */
struct cdl_jmp_patch  cdl_jmp_attach(void **target, void *detour);

/* Attach INT3 patch to target funciton.
 *
 * target: pointer to function pointer to
 * function to hook.
 * detour: function pointer to detour function
 */
struct cdl_swbp_patch cdl_swbp_attach(void **target, void *detour);

/* Detach JMP patch.
 *
 * jmp_patch: pointer to cdl_jmp_patch struct.
 */
void cdl_jmp_detach(struct cdl_jmp_patch *jmp_patch);

/* Detach INT3 patch.
 *
 * swbp_patch: pointer to cdl_swbp_patch struct.
 */
void cdl_swbp_detach(struct cdl_swbp_patch *swbp_patch);

/* Print JMP patch debug info.
 *
 * jmp_patch: pointer to cdl_jmp_patch struct.
 */
void cdl_jmp_dbg(struct cdl_jmp_patch *jmp_patch);

/* Print SW BP debug info.
 *
 * jmp_patch: pointer to cdl_swbp_patch struct.
 */
void cdl_swbp_dbg(struct cdl_swbp_patch *swbp_patch);

#endif
