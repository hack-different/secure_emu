import apple_data
import unicorn


class MachineState:
    def __init__(self):
        self.msr_data = apple_data.load_file("registers")

    def friendly_name(self, cp_reg: unicorn.unicorn.uc_arm64_cp_reg) -> str:
        msr_map = self.msr_data["aarch64"]["msr"]
        apple_map = self.msr_data["aarch64"]["apple_system_registers"]
        reg_descriptor = (
            f"S{cp_reg.op0}_{cp_reg.op1}_c{cp_reg.crn}_c{cp_reg.crm}_{cp_reg.op2}"
        )
        if reg_descriptor in msr_map:
            return msr_map[reg_descriptor]
        if reg_descriptor in apple_map:
            return apple_map[reg_descriptor]

        return "Unknown"
