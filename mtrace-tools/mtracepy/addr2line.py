import subprocess

class Addr2Line:
    def __init__(self, exePath):
        self.proc = subprocess.Popen([ 'addr2line', '-f', '-e', exePath],
                                     stdout = subprocess.PIPE,
                                     stdin = subprocess.PIPE)
        self.stdin = self.proc.stdin
        self.stdout = self.proc.stdout

    def __get(self, addr):
        self.stdin.write(str(addr) + '\n')
        func = self.stdout.readline().rstrip('\n\r')
        fileAndLine = self.stdout.readline().rstrip('\n\r')
        return func, fileAndLine

    def file(self, addr):
        func, fileAndLine = self.__get(addr)
        filename, sep, line = fileAndLine.partition(':')
        return filename

    def line(self, addr):
        func, fileAndLine = self.__get(addr)
        filename, sep, line = fileAndLine.partition(':')
        return line

    def func(self, addr):
        func, fileAndLine = self.__get(addr)
        return func
