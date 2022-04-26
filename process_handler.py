import sys
import subprocess
import time
import threading
import os

if sys.platform != 'win32':
    import fcntl
    import pty
    import tty


class PTY(object):
    pass


PTY = PTY()


class Process_handler:
    """reference:
    https://eli.thegreenplace.net/2017/interacting-with-a-long-running-child-process-in-python/

    This class is used to handle the vulnerable program execution.
    Below is a sample use of a program called system. Assuming
    the program internally calls 'system("/bin/sh")

    proc = Process_handler("system")
    proc.process()
    print(proc.recvuntil(delims=b'ello', timeout=5))
    print(proc.recvline())
    print("going interactive")
    proc.interactive()

    """
    PTY = PTY

    def __init__(self, program_name):
        self.program_name = program_name
        self.proc = None
        self.t = None
        self.pty = None
        self.preexec_fn = lambda: None

    def process(self, argument_str=""):
        # this is used instead of PIPE so that we can get the
        # buffer of the output as soon as possible
        stdin = subprocess.PIPE
        stdout = PTY

        handles = (stdin, stdout)
        self.pty = handles.index(PTY) if PTY in handles else None
        master = slave = None
        master, slave = pty.openpty()
        tty.setraw(master)
        tty.setraw(slave)
        stdout = slave

        # debug the pty
        # print(self.pty)

        self.proc = subprocess.Popen([f'./{self.program_name}', argument_str],
                                     stdin=subprocess.PIPE,
                                     stdout=stdout,
                                     stderr=subprocess.STDOUT,
                                     preexec_fn=self.__preexec_fn)

        self.proc.stdout = os.fdopen(os.dup(master), 'r+b', 0)
        os.close(master)
        os.close(slave)

        if self.proc.stdout:
            fd = self.proc.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        # let's give it a second to sleep a bit
        time.sleep(0.5)

    def __preexec_fn(self):
        # child_name = os.ttyname(self.pty)
        # this idea is from pwntools, creates a file handle from tty
        try:
            fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
            if fd >= 0:
                os.close(fd)
        except OSError:
            pass

        self.preexec_fn()

    def recvuntil(self, delims=b'', timeout=5):
        timeout_start = time.time()
        time.sleep(0.2)
        buffer = b''
        while time.time() < timeout_start + timeout:
            i = self.proc.stdout.read(1)
            if i is not None:
                buffer = buffer + i
            if buffer.find(delims) >= 0:
                break
        return buffer

    def recvline(self, timeout=5):
        return self.recvuntil(delims=b'\n', timeout=timeout)

    def interactive(self):
        go = threading.Event()

        def recv_thread(proc):
            while not go.isSet():
                try:
                    if self.proc.stdout.closed is False:
                        x = proc.stdout.read(1)
                        if x is not None:
                            print(x.decode("utf-8"), end='')
                except EOFError:
                    print('Got EOF while reading in interactive')
                    break
                except IOError:
                    pass

        t = threading.Thread(target=recv_thread, args=(self.proc,))
        t.start()

        try:
            time.sleep(1)
            while not go.isSet():
                data = sys.stdin.read(1)
                data = data.encode('utf_8')
                if data:
                    try:
                        self.proc.stdin.write(data)
                        self.proc.stdin.flush()
                    except EOFError:
                        go.set()
                        print('Got EOF while sending in interactive')
                        break
                    except IOError:
                        go.set()
                        print('Got EOF while sending in interactive')
                        break
                else:
                    go.set()
        finally:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=1)
                print('Process exited')
            except subprocess.TimeoutExpired:
                print('Process ended')
        t.join(timeout=0.1)
