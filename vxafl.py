import os
import subprocess
from avatar2 import *

WORK_DIR = "/home/ss/work/vxafl"
HOME = "/home/ss"
QEMU_VERSION = "2.10.0"
CPU_TARGET = "i386"
IMAGE_PATH = f"{HOME}/work/MS-DOS.vmdk"
VXWORKS_PATH = f"{HOME}/work/vxWorks"
FUZZ_IN = "./fuzzin"
FUZZ_OUT = "./fuzzout"
QEMU_EXEC = f"{WORK_DIR}/qemu-{QEMU_VERSION}/{CPU_TARGET}-softmmu/qemu-system-i386 -hda {IMAGE_PATH} -s -nographic"
cmdline = QEMU_EXEC.split(' ')
print(cmdline)
avatar = Avatar(arch=archs.X86)
target = avatar.add_target(GDBTarget, gdb_port=1234)

subprocess.Popen(cmdline, pass_fds=(199, 198))
# subprocess.Popen(cmdline)
target.init()  # connect the target
target.set_breakpoint("*{}".format(0x30d4d0))
while True:
    target.cont()
    target.wait()
    # esp = target.read_register('esp')
    # arg_addr = target.read_memory(esp+4, 4)
    # input_file = open(f"{WORK_DIR}/fuzzout/.cur_input", "rb")
    # test_case = input_file.read()
    # input_file.close()
    # arg_value_addr = target.read_memory(arg_addr, 4)
    # print(f"arg_addr:{arg_value_addr}")
    # target.write_memory(arg_value_addr, len(test_case), test_case)

