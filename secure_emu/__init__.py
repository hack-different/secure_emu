import typing

import unicorn
import machine_state
import image_loader

RegisterHook = typing.Callable[[int], int]


class SecureEMU:
    _core: image_loader.Core
    register_bank = {}
    register_hooks: dict[str, RegisterHook]

    def __init__(self, core: int):
        self._core = image_loader.ImageLoader.get_core(core)
        self._machine_state = machine_state.MachineState()

    @staticmethod
    def cp_reg_to_id(cp_reg: unicorn.unicorn.uc_arm64_cp_reg) -> str:
        return f"c{cp_reg.crn}_c{cp_reg.crm}_{cp_reg.op1}_{cp_reg.op2}"

    @staticmethod
    def _hook_block(uc, address, size, user_data):
        print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))

    @staticmethod
    def _hook_code(uc, address, size, user_data):
        print(
            ">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size)
        )

    @staticmethod
    def _hook_mrs(uc: unicorn.Uc, reg, cp_reg, reg_file) -> bool:
        pc = uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC)
        reg_friendly = msr_util.friendly_name(cp_reg)
        print(
            f">>> Hook MRS read instruction ({pc:x}): reg = 0x{reg:x}(UC_ARM64_REG_X2) cp_reg = {cp_reg}\n>>>\t{reg_friendly}"
        )
        reg_id = _cp_reg_to_id(cp_reg)
        if reg_id not in reg_file:
            reg_file[reg_id] = 0

        uc.reg_write(reg, reg_file[reg_id])
        uc.reg_write(unicorn.arm64_const.UC_ARM64_REG_PC, pc + 4)
        # Skip MRS instruction

        return True

    def _hook_msr(self, uc: unicorn.Uc, reg, cp_reg, reg_file) -> bool:
        pc = uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC)
        reg_friendly = msr_util.friendly_name(cp_reg)
        print(
            f">>> Hook MSR store instruction ({pc:x}): reg = 0x{reg:x}(UC_ARM64_REG_X2) cp_reg = {cp_reg}\n>>>\t{reg_friendly}"
        )
        reg_id = SecureEMU._cp_reg_to_id(cp_reg)
        reg_value = uc.reg_read(reg)
        if reg_id in self.register_hooks:
            value_to_store = self.register_hooks[reg_id](reg_value)
            reg_file[reg_id] = value_to_store
        else:
            reg_file[reg_id] = reg_value
        uc.reg_write(unicorn.arm64_const.UC_ARM64_REG_PC, pc + 4)
        # Skip MRS instruction

        return True

    @staticmethod
    def _hook_mem_invalid(mu: unicorn.Uc, access, address, size, value, user_data):
        ip = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC)
        match access:
            case unicorn.UC_MEM_FETCH:
                access_type = "FETCH"
            case unicorn.UC_MEM_READ:
                access_type = "READ"
            case unicorn.UC_MEM_WRITE:
                access_type = "WRITE"
            case other:
                access_type = f"UNKNOWN <{access:x}>"

        error = f">>> {access_type} ACCESS at 0x{address:016x} from IP = 0x{ip:016x}, data size = {size}, data value = 0x{value:x}"
        print(error)

    def run(self):
        mu = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
        mu.mem_map(self._core.image_base, self._core.image_size, unicorn.UC_PROT_EXEC | unicorn.UC_PROT_READ)

        mu.mem_write(self._core.image_base, self._core.secure_rom)

        mu.mem_map(self._core.sram_base, self._core.sram_size, unicorn.UC_PROT_ALL)

        def cache_as_ram_helper(value) -> int:
            if value & 0x01:
                return 0x8000000000000000 | value
            else:
                return value

        self.register_hooks["c15_c7_3_0"] = cache_as_ram_helper






        # mu.hook_add(unicorn.UC_HOOK_BLOCK, hook_block)
        mu.hook_add(unicorn.UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid)
        mu.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED, hook_mem_invalid)
        mu.hook_add(unicorn.UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)

        mu.hook_add(
            unicorn.UC_HOOK_INSN,
            hook_mrs,
            self.register_bank,
            1,
            0,
            unicorn.arm64_const.UC_ARM64_INS_MRS,
        )
        mu.hook_add(
            unicorn.UC_HOOK_INSN,
            hook_msr,
            self.register_bank,
            1,
            0,
            unicorn.arm64_const.UC_ARM64_INS_MSR,
        )

        try:
            mu.emu_start(0x100000000, 0x100000000 + len(rom), 0, 100000)
        except unicorn.UcError as e:
            print(e)




