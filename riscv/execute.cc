// See LICENSE for license details.

#include "processor.h"
#include "mmu.h"
#include "disasm.h"
#include <cassert>


static void commit_log_stash_privilege(processor_t* p)
{
#ifdef RISCV_ENABLE_COMMITLOG
  state_t* state = p->get_state();
  state->last_inst_priv = state->prv;
  state->last_inst_xlen = p->get_xlen();
  state->last_inst_flen = p->get_flen();
#endif
}

static void commit_log_print_value(int width, uint64_t hi, uint64_t lo)
{
  switch (width) {
    case 16:
      fprintf(stderr, "0x%04" PRIx16, (uint16_t)lo);
      break;
    case 32:
      fprintf(stderr, "0x%08" PRIx32, (uint32_t)lo);
      break;
    case 64:
      fprintf(stderr, "0x%016" PRIx64, lo);
      break;
    case 128:
      fprintf(stderr, "0x%016" PRIx64 "%016" PRIx64, hi, lo);
      break;
    default:
      abort();
  }
}

static void commit_log_print_insn(state_t* state, reg_t pc, insn_t insn)
{
#ifdef RISCV_ENABLE_COMMITLOG
  auto& reg = state->log_reg_write;
  int priv = state->last_inst_priv;
  int xlen = state->last_inst_xlen;
  int flen = state->last_inst_flen;

  // fprintf(stderr, "  {\"priv\":%1d,\"pc\":\"", priv);
  // commit_log_print_value(xlen, 0, pc);
  // fprintf(stderr, "\",\"insn\":\"");
  // commit_log_print_value(insn.length() * 8, 0, insn.bits());
  // fpintf(stderr, "\"}\n");

  if (reg.addr) {
    bool fp = reg.addr & 1;
    int rd = reg.addr >> 1;
    int size = fp ? flen : xlen;
    // fprintf(stderr, ",\"op\":{\"kind\":\"reg\",\"size\":\"%d\",\"addr\":\"0x%02x\",\"value\":\"", size, rd);
    // commit_log_print_value(size, reg.data.v[1], reg.data.v[0]);
    // fprintf(stderr, "\"}");
  }
  reg.addr = 0;
#endif
}

inline void processor_t::update_histogram(reg_t pc)
{
#ifdef RISCV_ENABLE_HISTOGRAM
  pc_histogram[pc]++;
#endif
}

// This is expected to be inlined by the compiler so each use of execute_insn
// includes a duplicated body of the function to get separate fetch.func
// function calls.
static reg_t execute_insn(processor_t* p, reg_t pc, insn_fetch_t fetch)
{
  commit_log_stash_privilege(p);
  reg_t npc = fetch.func(p, fetch.insn, pc);
  if (npc != PC_SERIALIZE_BEFORE) {
    commit_log_print_insn(p->get_state(), pc, fetch.insn);
    p->update_histogram(pc);
  }
  return npc;
}

bool processor_t::slow_path()
{
  return debug || state.single_step != state.STEP_NONE || state.dcsr.cause;
}

void processor_t::print_state()
{
  pthread_mutex_lock(json_log_fd_lock);
  fprintf(json_log_fd, "\n{\"kind\":\"mark\"}");
  fprintf(json_log_fd, "\n{\"kind\":\"state\",");
  fprintf(json_log_fd, "\"id\":%d,", id);

  fprintf(json_log_fd, "\"pc\":\"0x%" PRIx64 "\",", state.pc);
  fprintf(json_log_fd, "\"prv\":\"0x%" PRIx64 "\",", state.prv);
  fprintf(json_log_fd, "\"misa\":\"0x%" PRIx64 "\",", state.misa);
  fprintf(json_log_fd, "\"mstatus\":\"0x%" PRIx64 "\",", state.mstatus);
  fprintf(json_log_fd, "\"mepc\":\"0x%" PRIx64 "\",", state.mepc);
  fprintf(json_log_fd, "\"mtval\":\"0x%" PRIx64 "\",", state.mtval);
  fprintf(json_log_fd, "\"mscratch\":\"0x%" PRIx64 "\",", state.mscratch);
  fprintf(json_log_fd, "\"mtvec\":\"0x%" PRIx64 "\",", state.mtvec);
  fprintf(json_log_fd, "\"mcause\":\"0x%" PRIx64 "\",", state.mcause);
  fprintf(json_log_fd, "\"minstret\":\"0x%" PRIx64 "\",", state.minstret);
  fprintf(json_log_fd, "\"mie\":\"0x%" PRIx64 "\",", state.mie);
  fprintf(json_log_fd, "\"mip\":\"0x%" PRIx64 "\",", state.mip);
  fprintf(json_log_fd, "\"medeleg\":\"0x%" PRIx64 "\",", state.medeleg);
  fprintf(json_log_fd, "\"mideleg\":\"0x%" PRIx64 "\",", state.mideleg);
  fprintf(json_log_fd, "\"mcounteren\":\"0x%" PRIx64 "\",", state.mcounteren);
  fprintf(json_log_fd, "\"scounteren\":\"0x%" PRIx64 "\",", state.scounteren);
  fprintf(json_log_fd, "\"sepc\":\"0x%" PRIx64 "\",", state.sepc);
  fprintf(json_log_fd, "\"stval\":\"0x%" PRIx64 "\",", state.stval);
  fprintf(json_log_fd, "\"sscratch\":\"0x%" PRIx64 "\",", state.sscratch);
  fprintf(json_log_fd, "\"stvec\":\"0x%" PRIx64 "\",", state.stvec);
  fprintf(json_log_fd, "\"satp\":\"0x%" PRIx64 "\",", state.satp);
  fprintf(json_log_fd, "\"scause\":\"0x%" PRIx64 "\",", state.scause);

  fprintf(json_log_fd, "\"xregs\":[");
  for (int reg_i = 0; reg_i < NXPR; reg_i++) {
    if (reg_i != 0)
      fprintf(json_log_fd, ",");
    fprintf(json_log_fd, "\"0x%" PRIx64 "\"", state.XPR[reg_i]);
  }
  fprintf(json_log_fd, "]}");

  // fprintf(json_log_fd, "\"fregs\":[");
  // for (int reg_i = 0; reg_i < NFPR; reg_i++) {
  //   if (reg_i != 0)
  //     fprintf(json_log_fd, ",");
  //   fprintf(json_log_fd, "\"0x%016" PRIx64 "\"", state.FPR[reg_i]);
  // }
  // fprintf(json_log_fd, "]}");

  fflush(json_log_fd);
  pthread_mutex_unlock(json_log_fd_lock);

  get_mmu()->flush_tlb();
}

// fetch/decode/execute loop
void processor_t::step(size_t n)
{
  if (state.pc == 0xffffffe0003c3bf4) {
    throw "endod";
  }

  print_state();

  n = 1;
  mmu->flush_tlb();

  if (state.dcsr.cause == DCSR_CAUSE_NONE) {
    if (halt_request) {
      enter_debug_mode(DCSR_CAUSE_DEBUGINT);
    } // !!!The halt bit in DCSR is deprecated.
    else if (state.dcsr.halt) {
      enter_debug_mode(DCSR_CAUSE_HALT);
    }
  }

  while (n > 0) {
    size_t instret = 0;
    reg_t pc = state.pc;
    mmu_t* _mmu = mmu;

    #define advance_pc() \
     if (unlikely(invalid_pc(pc))) { \
       switch (pc) { \
         case PC_SERIALIZE_BEFORE: state.serialized = true; break; \
         case PC_SERIALIZE_AFTER: ++instret; break; \
         case PC_SERIALIZE_WFI: n = ++instret; break; \
         default: abort(); \
       } \
       pc = state.pc; \
       break; \
     } else { \
       state.pc = pc; \
       instret++; \
     }

    try
    {
      take_pending_interrupt();

      // if (unlikely(slow_path()))
      if (1)
      {
        while (instret < n)

        {
          if (unlikely(!state.serialized && state.single_step == state.STEP_STEPPED)) {
            state.single_step = state.STEP_NONE;
            if (state.dcsr.cause == DCSR_CAUSE_NONE) {
              enter_debug_mode(DCSR_CAUSE_STEP);
              // enter_debug_mode changed state.pc, so we can't just continue.
              break;
            }
          }

          if (unlikely(state.single_step == state.STEP_STEPPING)) {
            state.single_step = state.STEP_STEPPED;
          }

          insn_fetch_t fetch = mmu->load_insn(pc);
          if (debug && !state.serialized)
            disasm(fetch.insn);

          insn_t insn = fetch.insn;
          uint64_t bits = insn.bits() & ((1ULL << (8 * insn_length(insn.bits()))) - 1);

          pthread_mutex_lock(json_log_fd_lock);
          fprintf(json_log_fd, "\n{\"kind\":\"insn\",\"core\":%d,\"pc\":\"0x%" PRIx64 "\",\"bits\":\"0x%08" PRIx64 "\",\"desc\":\"%s\"}",
            id, state.pc, bits, disassembler->disassemble(insn).c_str());
          fflush(json_log_fd);
          pthread_mutex_unlock(json_log_fd_lock);

          pc = execute_insn(this, pc, fetch);
          
          advance_pc();

          if (unlikely(state.pc >= DEBUG_ROM_ENTRY &&
                       state.pc < DEBUG_END)) {
            // We're waiting for the debugger to tell us something.
            return;
          }

        }
      }
      else while (instret < n)
      {
        // This code uses a modified Duff's Device to improve the performance
        // of executing instructions. While typical Duff's Devices are used
        // for software pipelining, the switch statement below primarily
        // benefits from separate call points for the fetch.func function call
        // found in each execute_insn. This function call is an indirect jump
        // that depends on the current instruction. By having an indirect jump
        // dedicated for each icache entry, you improve the performance of the
        // host's next address predictor. Each case in the switch statement
        // allows for the program flow to contine to the next case if it
        // corresponds to the next instruction in the program and instret is
        // still less than n.
        //
        // According to Andrew Waterman's recollection, this optimization
        // resulted in approximately a 2x performance increase.

        // This figures out where to jump to in the switch statement
        size_t idx = _mmu->icache_index(pc);

        // This gets the cached decoded instruction from the MMU. If the MMU
        // does not have the current pc cached, it will refill the MMU and
        // return the correct entry. ic_entry->data.func is the C++ function
        // corresponding to the instruction.
        auto ic_entry = _mmu->access_icache(pc);

        // This macro is included in "icache.h" included within the switch
        // statement below. The indirect jump corresponding to the instruction
        // is located within the execute_insn() function call.
        #define ICACHE_ACCESS(i) { \
          insn_fetch_t fetch = ic_entry->data; \
          pc = execute_insn(this, pc, fetch); \
          ic_entry = ic_entry->next; \
          if (i == mmu_t::ICACHE_ENTRIES-1) break; \
          if (unlikely(ic_entry->tag != pc)) break; \
          if (unlikely(instret+1 == n)) break; \
          instret++; \
          state.pc = pc; \
        }

        // This switch statement implements the modified Duff's device as
        // explained above.
        switch (idx) {
          // "icache.h" is generated by the gen_icache script
          #include "icache.h"
        }

        advance_pc();
      }
    }
    catch(trap_t& t)
    {
      take_trap(t, pc);
      n = instret;

      if (unlikely(state.single_step == state.STEP_STEPPED)) {
        state.single_step = state.STEP_NONE;
        enter_debug_mode(DCSR_CAUSE_STEP);
      }
    }
    catch (trigger_matched_t& t)
    {
      fprintf(stderr, "\n\nCaught trigger_matched_t\n\n");

      if (mmu->matched_trigger) {
        // This exception came from the MMU. That means the instruction hasn't
        // fully executed yet. We start it again, but this time it won't throw
        // an exception because matched_trigger is already set. (All memory
        // instructions are idempotent so restarting is safe.)

        insn_fetch_t fetch = mmu->load_insn(pc);
        pc = execute_insn(this, pc, fetch);
        advance_pc();

        delete mmu->matched_trigger;
        mmu->matched_trigger = NULL;
      }
      switch (state.mcontrol[t.index].action) {
        case ACTION_DEBUG_MODE:
          enter_debug_mode(DCSR_CAUSE_HWBP);
          break;
        case ACTION_DEBUG_EXCEPTION: {
          mem_trap_t trap(CAUSE_BREAKPOINT, t.address);
          take_trap(trap, pc);
          break;
        }
        default:
          abort();
      }
    }

    state.minstret += instret;
    n -= instret;
  }

}
