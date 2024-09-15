#by huowuzhao
import os
import stat
import subprocess

'''
关键检测要点：
1、Shell反弹特征：
  文件描述符号0（stdin）会被重定向到Socket文件。
  文件描述符号1（stdout）和2（stderr）会被重定向到Socket文件。
2、Socket反弹特征：
  产生套接口文件描述符与外界通信（FD最小的通常是0、1、2）。
  生成一个SHELL子进程，子进程继承了父进程的FD，FD 0 会复制套接字的文件描述符。
3、进程反弹特征：
  产生进程间通信的管道文件（FIFO）。
  文件描述符0（stdin）指向管道。
  文件描述符1（stdout）和文件描述符2（stderr）指向管道。
  生成一个长期存在且通过管道通信的SHELL进程。
4、管道符反弹特征：
  文件描述符1（stdout）指向管道。
  文件描述符0和其他可读写文件描述符（如2）指向同一个套接字文件。
'''

def is_socket(fd_path):
    """ 检查文件描述符是否是Socket类型 """
    try:
        mode = os.stat(fd_path).st_mode
        return stat.S_ISSOCK(mode)
    except Exception as e:
        return False

def is_pipe(fd_path):
    """ 检查文件描述符是否是管道类型 """
    try:
        mode = os.stat(fd_path).st_mode
        return stat.S_ISFIFO(mode)
    except Exception as e:
        return False

def get_fd_info(pid):
    """ 获取指定PID的文件描述符信息 """
    fd_dir = f'/proc/{pid}/fd'
    fd_info = {}

    try:
        for fd in os.listdir(fd_dir):
            fd_path = os.path.join(fd_dir, fd)
            if os.path.islink(fd_path):
                target = os.readlink(fd_path)
                fd_info[int(fd)] = target
    except Exception as e:
        print(f"无法访问进程 {pid} 的文件描述符: {e}")
        return {}

    return fd_info

def check_shell_rebound(pid):
    """ 检查Shell反弹特征 """
    fd_info = get_fd_info(pid)

    if all(is_socket(f'/proc/{pid}/fd/{fd}') for fd in [0, 1, 2]):
        print(f"进程 {pid} 符合Shell反弹特征")
        return True
    else:
        print(f"进程 {pid} 不符合Shell反弹特征")
        return False

def check_socket_rebound(pid):
    """ 检查Socket反弹特征 """
    fd_info = get_fd_info(pid)

    # 检查是否有最小的FD是Socket，且创建了SHELL子进程
    if all(is_socket(f'/proc/{pid}/fd/{fd}') for fd in [0]):
        print(f"进程 {pid} 可能具有与外界通信的Socket反弹特征")
        # 查找子进程是否继承了Socket
        child_pids = subprocess.check_output(f'pgrep -P {pid}', shell=True).decode().split()
        for child_pid in child_pids:
            child_fd_info = get_fd_info(child_pid)
            if child_fd_info and any(is_socket(f'/proc/{child_pid}/fd/{fd}') for fd in [0, 1, 2]):
                print(f"子进程 {child_pid} 继承了Socket文件描述符，可能是反弹Shell")
                return True
    print(f"进程 {pid} 不符合Socket反弹特征")
    return False

def check_process_rebound(pid):
    """ 检查进程反弹特征 """
    fd_info = get_fd_info(pid)

    if all(is_pipe(f'/proc/{pid}/fd/{fd}') for fd in [0, 1]):
        print(f"进程 {pid} 符合进程间通信的管道反弹特征")
        # 检查是否是一个Shell进程
        cmdline_path = f'/proc/{pid}/cmdline'
        with open(cmdline_path, 'r') as f:
            cmdline = f.read()
            if 'sh' in cmdline or 'bash' in cmdline:
                print(f"进程 {pid} 是一个Shell进程，且符合反弹特征")
                return True
    print(f"进程 {pid} 不符合进程反弹特征")
    return False

def check_pipe_rebound(pid):
    """ 检查管道符反弹特征 """
    fd_info = get_fd_info(pid)

    if is_pipe(f'/proc/{pid}/fd/1') and all(is_socket(f'/proc/{pid}/fd/{fd}') for fd in [0, 2]):
        print(f"进程 {pid} 符合管道符反弹特征")
        return True
    else:
        print(f"进程 {pid} 不符合管道符反弹特征")
        return False

if __name__ == '__main__':
    pid = input("请输入要检查的进程PID: ")

    print("\n[检测Shell反弹特征]")
    check_shell_rebound(pid)

    print("\n[检测Socket反弹特征]")
    check_socket_rebound(pid)

    print("\n[检测进程反弹特征]")
    check_process_rebound(pid)

    print("\n[检测管道符反弹特征]")
    check_pipe_rebound(pid)
