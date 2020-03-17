#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket, signal
import threading, getopt, sys, string, time, random
from time import sleep

default_lcl_addr = '127.0.0.1'
default_lcl_port = 22535
max_list = 50

def usage():
    print """
    -h --help       print the help
    -t --type       [client or server]
    -l --list       Max number of connection
    -a --addr       To monitor the ip address
    -p --port       To monitor the port number
    """

try:
    opts, args = getopt.getopt(sys.argv[1:], "ht:a:p:l:", ["help=", "type=", "addr=", "port=", "list="])
    print (opts, args)
    for op, value in opts:
        if op in ("-l", "--list"):
            list = string.atol(value)
        elif op in ("-t", "--type"):
            type = value
        elif op in ("-a", "--addr"):
            addr = value
        elif op in ("-p", "--port"):
            port = string.atol(value)
        elif op in ("-h", "--help"):
            usage()
            sys.exit()
except Exception as e:
    print '--> the format is valid with Exception: %s' % e
    usage()
    exit(1)

def socket_service(fd_client, address):
    try:
        fd_client.settimeout(300)
        while True:
            buf = fd_client.recv(2048)
            if len(buf) > 0:
                buf = "<%s> <-- <%s>" % (address, buf)
                print(buf)
                fd_client.send(buf)
            else:
                print(address)
                print("====client <%s:%d> is disconnected...====\n" % (address[0], address[1]))
                break
    except socket.timeout:
        print("time out")
    fd_client.close()

def retry_connect(fd_socket, retry = 3):
    if retry == 0:
        print('...fd_socket<%s> connect failed...' % (fd_socket))
        sys.exit(1)
    try:
        print('---> <%s:%s>' % (addr, port))
        fd_socket.connect((addr, port))
        print('---> connect successfully')
    except socket.gaierror, e:
        print('Address-related error connecting to server: %s, and retry <%d>' % (e, retry))
        retry_connect(fd_socket, retry - 1)
    except Exception, e:
        print('...fd_socket<%s> connect failed with error<%s>...' % (fd_socket, str(e)))
        if 'Errno 111' in str(e):
            sleep(2)
            retry_connect(fd_socket, retry - 1)
        sys.exit(1)

def socket_client(lcl_ip, lcl_port):
    fd_service = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('===> fd_service is %s' % fd_service)
    fd_service.bind((lcl_ip, lcl_port))
    print('===> bind <%s:%s>' % (lcl_ip, lcl_port))
    retry_connect(fd_service, 3)
    print('===> connect successfully')

    message = "I want to change the world!"
    for i in range(1, 5):
        buf = "<%d> --> %s" % (i, message)
        fd_service.send(buf)
        recv_buf = fd_service.recv(2048)
        if recv_buf > 0:
            print 'ServerOutput:' + recv_buf
            time_wait = random.randint(1, 2)
            time.sleep(time_wait)
        else:
            print '==== link between <%s:%d> and <%s:%d> is disconnected, recover it ...' % (lcl_ip, lcl_port, addr, port)
            fd_service.close()
            time.sleep(1)
            break

    fd_service.close()

def wait_for_all_thread_exit(thread_pool):
    while True:
        alive = False
        for thread in thread_pool:
            alive = alive or thread.isAlive()
        if not alive:
            break

def main_service():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((addr, port))
    sock.listen(list)

    thread_pool = []

    while True:
        fd_client, address = sock.accept()
        thread_name = 'thread_%s_%d' % (address[0], address[1])
        thread = threading.Thread(target = socket_service, args = (fd_client, address), name = thread_name)
        thread.setDaemon(True)
        thread_pool.append(thread)
        thread.start()
    wait_for_all_thread_exit(thread_pool)

def main_client():
    port = random.randint(15000, 15600)
    lcl_addr = [
        {'ip':'172.17.0.1', 'port':port},
    ]

    thread_pool = []

    for lcl_address in lcl_addr:
        thread = threading.Thread(target = socket_client, args = (lcl_address['ip'], lcl_address['port'], ), name = 'client_%s_%d' % (lcl_address['ip'], lcl_address['port']))
        thread.setDaemon(True)
        thread_pool.append(thread)
        thread.start()
    wait_for_all_thread_exit(thread_pool)

def sig_handler(sig, frame):
    print('---> receive a signal %d, exit' % (sig))
    exit(1)

if __name__ == '__main__':
    #set signal handler
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    if type == 'client':
        main_client()
    elif type == 'server':
        print 'xxxx'
        main_service()
