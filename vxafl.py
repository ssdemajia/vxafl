import os
import subprocess
from avatar2 import *

WORK_DIR = "/home/ss/work/vxafl"
HOME = "/home/ss"
QEMU_VERSION = "2.10.0"
CPU_TARGET = "i386"
VXWORKS_VERSION = "6.8"
IMAGE_PATH = f"{HOME}/work/vxworks{VXWORKS_VERSION}/MS-DOS.vmdk"
VXWORKS_PATH = f"{HOME}/work/vxworks{VXWORKS_VERSION}/vxWorks"
# QEMU_EXEC = f"{WORK_DIR}/qemu-{QEMU_VERSION}/{CPU_TARGET}-softmmu/qemu-system-i386 -hda {IMAGE_PATH} -nographic -s -vxafl-img {VXWORKS_PATH} -vxafl-entry svcudp_recv -net tap,ifname=tap0 -net nic,model=pcnet"
QEMU_EXEC = f"{WORK_DIR}/qemu-{QEMU_VERSION}/{CPU_TARGET}-softmmu/qemu-system-i386 -hda {IMAGE_PATH} -s -nographic -vxafl-img {VXWORKS_PATH} -vxafl-entry CrashFunc"
cmdline = QEMU_EXEC.split(' ')
print(QEMU_EXEC)
avatar = Avatar(arch=archs.X86)
target = avatar.add_target(GDBTarget, gdb_port=1234)

subprocess.Popen(cmdline, pass_fds=(199, 198))
# subprocess.Popen(cmdline)

target.init()  # connect the target
# target.set_breakpoint("svcudp_recv")
# target.set_breakpoint("CrashFunc")
# target.set_breakpoint("*{}".format(0x3a0817))
# target.set_breakpoint("*{}".format(0x3a084c))
# target.set_breakpoint("*{}".format(0x3a0849))
# target.set_breakpoint("*{}".format(0x39f12c)) # 返回地址
target.set_breakpoint("*{}".format(0x30d4d0))
in_the_entry = False

while True:
    target.cont()
    target.wait()
    if not in_the_entry:
        # target.set_breakpoint("excStub")
        # target.set_breakpoint("excPanicShow")
        # target.set_breakpoint("excStub0")
        # target.set_breakpoint("reschedule")
        # target.set_breakpoint("idleEnter")
        # target.set_breakpoint("excTask")
        target.set_breakpoint("*{}".format(0x3189e0)) # excStub
        target.set_breakpoint("*{}".format(0x40cb30))
        target.set_breakpoint("*{}".format(0x40a250))
        # target.set_breakpoint("*{}".format(0x312d50)) #excPanicShow
        # target.set_breakpoint("*{}".format(0x00318a50)) # excStub1
        in_the_entry = True
    # print("complete one")

