"""HELD container entry gate. Blocks until the owner writes ONE byte to stdin, then execs the fixed target.

The owner holds the stdin pipe, observes the started container (pid, cgroup, namespaces) and binds identity BEFORE
writing the byte. EOF without the byte (owner died or gave up) exits 3 and never runs the target. Runs nothing at import.
"""
import os
import sys

APPROVED_FOR_EXECUTION = False
TARGETS = ('/fixture/contained_driver.py', '/fixture/control_driver.py')


def main(argv=None, *, stdin_fd=0, execv=os.execv):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] not in TARGETS or argv[1] != '/work':
        return 2
    if os.read(stdin_fd, 1) != b'\x01':
        return 3
    execv(sys.executable, [sys.executable, argv[0], argv[1]])
    return 4


if __name__ == '__main__':
    os._exit(main())
