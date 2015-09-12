#include "lambchop.h"

#include <assert.h>

#define ERR(...) lambchop_err(logger, __VA_ARGS__)
#define INFO(...) lambchop_info(logger, __VA_ARGS__)
#define DEBUG(...) lambchop_debug(logger, __VA_ARGS__)

#define IS_REX(rex) (((rex) & 0xf0) == 0x40)
#define IS_REX_W(rex) ((rex) & 0x08)
#define IS_REX_R(rex) ((rex) & 0x04)
#define IS_REX_X(rex) ((rex) & 0x02)
#define IS_REX_B(rex) ((rex) & 0x01)
#define REX_REG_BIT 0x10

#define REGISTER_RAX 0x00
#define REGISTER_RCX 0x01
#define REGISTER_RDX 0x02
#define REGISTER_RBX 0x03
#define REGISTER_RSP 0x04
#define REGISTER_RBP 0x05
#define REGISTER_RSI 0x06
#define REGISTER_RDI 0x07
#define REGISTER_R8  (REX_REG_BIT & 0x00)
#define REGISTER_R9  (REX_REG_BIT & 0x01)
#define REGISTER_R10 (REX_REG_BIT & 0x02)
#define REGISTER_R11 (REX_REG_BIT & 0x03)
#define REGISTER_R12 (REX_REG_BIT & 0x04)
#define REGISTER_R13 (REX_REG_BIT & 0x05)
#define REGISTER_R14 (REX_REG_BIT & 0x06)
#define REGISTER_R15 (REX_REG_BIT & 0x07)

static const char *regnames[] = {
  "RAX",
  "RCX",
  "RDX",
  "RBX",
  "RSP",
  "RBP",
  "RSI",
  "RDI",
  "R8",
  "R9",
  "R10",
  "R11",
  "R12",
  "R13",
  "R14",
  "R15"
};

#define OPCODE_PUSH_RAX (0x50 | REGISTER_RAX)
#define OPCODE_PUSH_RCX (0x50 | REGISTER_RCX)
#define OPCODE_PUSH_RDX (0x50 | REGISTER_RDX)
#define OPCODE_PUSH_RBX (0x50 | REGISTER_RBX)
#define OPCODE_PUSH_RSP (0x50 | REGISTER_RSP)
#define OPCODE_PUSH_RBP (0x50 | REGISTER_RBP)
#define OPCODE_PUSH_RSI (0x50 | REGISTER_RSI)
#define OPCODE_PUSH_RDI (0x50 | REGISTER_RDI)

#define OPCODE_SUB 0x83

#define OPCODE_MOV_0X89 0x89

#define MODRM_REG(modrm) (((modrm) & 0x38) >> 3)
#define MODRM_MOD(modrm) (((modrm) & 0xc0) >> 6)
#define MODRM_RM(modrm) ((modrm) & 0x07)
#define MODRM_OP_EXT(modrm) (((modrm) & 0xc0) >> 6)
#define MODRM_MOD_MEM_DISP0 0
#define MODRM_MOD_MEM_DISP8 1
#define MODRM_MOD_MEM_DISP32 2
#define MODRM_MOD_REG 3


static inline uint8_t modrm_rex_reg(uint8_t modrm, uint8_t rex) {
  uint8_t reg = MODRM_REG(modrm);
  return IS_REX_R(rex) ? (REX_REG_BIT | reg) : reg;
}

static inline uint8_t modrm_rex_mod_rm(uint8_t modrm, uint8_t rex) {
  uint8_t mod = MODRM_MOD(modrm);
  uint8_t rm = MODRM_RM(modrm);
  assert(mod == MODRM_MOD_REG);
  return IS_REX_R(rex) ? (REX_REG_BIT | rm) : rm;
}

static inline uint8_t fetch_rex(uint64_t *ipp) {
  uint64_t ip = *ipp;
  uint8_t rex = (*((uint8_t*)ip));
  if (IS_REX(rex)) {
    *ipp = (ip + 1);
    return rex;
  } else {
    return 0;
  }
}

static inline uint8_t fetch_modrm(uint64_t *ipp) {
  uint64_t ip = *ipp;
  uint8_t opcode = (*((uint8_t*)ip));
  *ipp = (ip + 1);
  return opcode;
}

static inline uint8_t fetch_opcode(uint64_t *ipp) {
  uint64_t ip = *ipp;
  uint8_t opcode = (*((uint8_t*)ip));
  *ipp = (ip + 1);
  return opcode;
}

static inline char fetch_imm_sb(uint64_t *ipp) {
  uint64_t ip = *ipp;
  char imm = (*((char*)ip));
  *ipp = (ip + 1);
  return imm;
}

static int vm_main(uint8_t *p, lambchop_logger *logger) {
  uint64_t rip = (uint64_t)p;

  while (true) {
    uint8_t rex = fetch_rex(&rip);
    uint8_t opcode = fetch_opcode(&rip);
    uint8_t modrm;
    const char *src, *dst;
    switch(opcode) {
      case OPCODE_PUSH_RBP:
        DEBUG("PUSH EBP\n");
        break;
      case OPCODE_MOV_0X89:
        modrm = fetch_modrm(&rip);
        src = regnames[modrm_rex_reg(modrm, rex)];
        dst = regnames[modrm_rex_mod_rm(modrm, rex)];
        assert(IS_REX_W(rex));
        DEBUG("MOV %s %s\n", src, dst);
        break;
      case OPCODE_SUB:
        modrm = fetch_modrm(&rip);
        dst = regnames[modrm_rex_mod_rm(modrm, rex)];
        {
          char imm = fetch_imm_sb(&rip);
          DEBUG("SUB 0x%x %s\n", imm, dst);
        }
        break;
      default:
        ERR("unsupported opcode 0x%x\n", opcode);
        return -1;
    }
  }
}

int lambchop_vm_run(void *mainfunc, lambchop_logger *logger) {
  // TODO 引数を扱えるようにする。
  /*return ((int(*)(void))mainfunc)();*/
  return vm_main(mainfunc, logger);
}
