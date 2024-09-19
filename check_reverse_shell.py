#by huowuzhao
import os
import psutil
import stat
import socket

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
  参考: https://github.com/configworld768/linuxStack/tree/master/reser_shell
'''


def is_socket(fd_path):
    """Check if the file descriptor is a socket."""
    try:
        mode = os.stat(fd_path).st_mode
        return stat.S_ISSOCK(mode)
    except Exception:
        return False

def is_pipe(fd_path):
    """Check if the file descriptor is a pipe (FIFO)."""
    try:
        mode = os.stat(fd_path).st_mode
        return stat.S_ISFIFO(mode)
    except Exception:
        return False

def get_process_command(pid):
    """Get the command line of the process."""
    try:
        proc = psutil.Process(pid)
        cmdline = ' '.join(proc.cmdline())
        return cmdline
    except Exception:
        return ""

def get_network_connections(pid):
    """Get network connections of the process."""
    try:
        proc = psutil.Process(pid)
        connections = proc.net_connections(kind='inet')
        conn_info = []
        for conn in connections:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ''
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ''
            conn_info.append({
                'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                'local_address': laddr,
                'remote_address': raddr,
                'status': conn.status
            })
        return conn_info
    except Exception:
        return []

def check_shell_reverse_shell(pid):
    """Check for Shell reverse shell features."""
    # Condition 1: File descriptor 0 is redirected to a socket file
    fd0_path = f'/proc/{pid}/fd/0'
    fd1_path = f'/proc/{pid}/fd/1'
    fd2_path = f'/proc/{pid}/fd/2'

    cond1 = is_socket(fd0_path)
    # Condition 2: File descriptors 1 and 2 are redirected to socket files
    cond2 = is_socket(fd1_path) and is_socket(fd2_path)

    if cond1 and cond2:
        return True
    else:
        return False

def check_socket_reverse_shell(pid):
    """Check for Socket reverse shell features."""
    # Condition 1: Generate a socket file descriptor communicating with the outside world,
    # and it's the smallest available file descriptor (fd 0)
    fd0_path = f'/proc/{pid}/fd/0'
    cond1 = is_socket(fd0_path)

    # Condition 2: Has a SHELL subprocess that inherits file descriptors
    # Find child processes
    try:
        proc = psutil.Process(pid)
        child_procs = proc.children(recursive=True)
        cond2 = False
        for child in child_procs:
            # Check if child is a shell process
            child_cmd = ' '.join(child.cmdline())
            if 'sh' in child_cmd or 'bash' in child_cmd or 'zsh' in child_cmd:
                # Check if child inherits file descriptor 0
                child_fd0_path = f'/proc/{child.pid}/fd/0'
                try:
                    if os.path.samefile(fd0_path, child_fd0_path):
                        cond2 = True
                        break
                except Exception:
                    continue
    except Exception:
        cond2 = False

    if cond1 and cond2:
        return True
    else:
        return False

def check_process_reverse_shell(pid):
    """Check for Process reverse shell features."""
    fd0_path = f'/proc/{pid}/fd/0'
    fd1_path = f'/proc/{pid}/fd/1'

    # Condition 1: File descriptor 0 points to a pipe
    cond1 = is_pipe(fd0_path)

    # Condition 2: File descriptor 1 points to a pipe
    cond2 = is_pipe(fd1_path)

    # Condition 3: Generate a long-lived SHELL process pointing to the pipe
    # Check if the process is a shell process
    try:
        proc = psutil.Process(pid)
        cmdline = ' '.join(proc.cmdline())
        if 'sh' in cmdline or 'bash' in cmdline or 'zsh' in cmdline:
            cond3 = True
        else:
            cond3 = False
    except Exception:
        cond3 = False

    if cond1 and cond2 and cond3:
        return True
    else:
        return False

def check_pipe_symbol_reverse_shell(pid):
    """Check for Pipe symbol reverse shell features."""
    fd0_path = f'/proc/{pid}/fd/0'
    fd1_path = f'/proc/{pid}/fd/1'
    fd2_path = f'/proc/{pid}/fd/2'

    # Condition 1: fd 1 points to a pipe
    cond1 = is_pipe(fd1_path)

    # Condition 2: fd 0 and other readable/writable fds point to the same socket file
    cond2 = False
    if is_socket(fd0_path) and is_socket(fd2_path):
        try:
            if os.path.samefile(fd0_path, fd2_path):
                cond2 = True
        except Exception:
            cond2 = False

    if cond1 and cond2:
        return True
    else:
        return False

def main():
    pid_input = input("请输入要检测的进程 PID：")
    try:
        pid = int(pid_input)
    except ValueError:
        print("无效的 PID，请输入数字。")
        return

    if not psutil.pid_exists(pid):
        print(f"进程 {pid} 不存在。")
        return

    reverse_shell_detected = False

    if check_shell_reverse_shell(pid):
        print(f"进程 {pid} 符合 Shell 反弹特征。")
        reverse_shell_detected = True
    elif check_socket_reverse_shell(pid):
        print(f"进程 {pid} 符合 Socket 反弹特征。")
        reverse_shell_detected = True
    elif check_process_reverse_shell(pid):
        print(f"进程 {pid} 符合 进程反弹特征。")
        reverse_shell_detected = True
    elif check_pipe_symbol_reverse_shell(pid):
        print(f"进程 {pid} 符合 管道符反弹特征。")
        reverse_shell_detected = True
    else:
        print(f"进程 {pid} 不符合任何反弹特征。")

    if reverse_shell_detected:
        # Print command and network connection information
        cmdline = get_process_command(pid)
        print(f"命令行: {cmdline}")
        connections = get_network_connections(pid)
        if connections:
            print("网络连接信息：")
            for conn in connections:
                print(f"  协议: {conn['type']}, 本地地址: {conn['local_address']}, 远程地址: {conn['remote_address']}, 状态: {conn['status']}")
        else:
            print("未找到网络连接信息。")
    else:
        print("未检测到反弹 Shell。")

if __name__ == "__main__":
    main()
