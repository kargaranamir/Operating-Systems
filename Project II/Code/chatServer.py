#! /usr/bin/env python3
__author__ = 'Amirhossein Kargaran 9429523 '

import os
import sys
import socket

import pickle
import select
import signal
import threading
import time
from threading import Thread
from datetime import datetime

# Local modules
from APIs.logging import Log
from APIs.logging import Color
from APIs.security import *
from Crypto.Random import random
from filelock import FileLock
file_path = "result.txt"
lock_path = "result.txt.lock"
lock = FileLock(lock_path, timeout=1)

# Declare Global variables
PORT = 5558
TERMINATE = False
CLI_HASH = {}
KEY = ''
ll = list()

class Server():
    def __init__(self):
        self.HOST_IP = '0.0.0.0'
        self.HOST_PORT = '8081'
        self.MAX_USR_ACCPT = '100'

    def show_help(self):
        msg = '''
        AVAILABLE COMMANDS:
        \h          Print these information
        \d          Set default configuration
        \sd         Show default configuration
        \sc         Show current configuration
        \sau        Show active users
        \sac        Show active chat rooms
        \sf         Shutdown server forcefully
        \monitor    Enables monitor mode'''
        print(msg)

    def show_config(self, type_='default'):
        if type_ in ('active', 'ACTIVE'):
            msg = '''
            Active configuration of the server :
            HOST IP = ''' + self.HOST_IP + '''
            HOST PORT = ''' + self.HOST_PORT + '''
            MAX USER ALLOWED = ''' + self.MAX_USR_ACCPT 
            logging.log('Showing Active server configuration')
            print(msg)
        else:
            msg = '''
            Default configuration of the server:
            HOST IP = 0.0.0.0
            HOST PORT = 8081
            MAX USER ALLOWED = 100'''
            print(msg)

    def set_usr_config(self, parameters):
        if parameters:
            if sys.argv[1] in ('-h', '--help'):
                self.show_help()
            try:
                self.HOST_IP = sys.argv[1]
                self.HOST_PORT = sys.argv[2]
                self.MAX_USR_ACCPT = sys.argv[3]
            except:
                print('USAGE:\nscript ip_address port_number max_usr_accpt')
                sys.exit(0)
        else:
            self.HOST_IP = input('Enter host IP : ')
            self.HOST_PORT = input('Enter host PORT : ')
            self.MAX_USR_ACCPT = input('Enter max number of users server would accept : ')

    def update_active_users(self):
        self.user_list = []
        for cli_obj in CLI_HASH.values():
            self.user_list.append(cli_obj.userName)

    def signal_handler(self, signal, frame):
        print(' has been pressed.\n')

    def srv_prompt(self):
        # TODO: Add feature to view server socket status
        global TERMINATE
        while True:
            opt = input(Color.PURPLE + '\nenter command $ ' + Color.ENDC)
            if opt == '\h':
                self.show_help()
            elif opt == '\monitor':
                print('Monitoring mode ENABLED!')
                logging.silent_flag = False
                signal.signal(signal.SIGINT, self.signal_handler)
                signal.pause()
                print('Monitoring mode DISABLED')
                logging.silent_flag = True
            elif opt == '\sd':
                self.show_config(type_='default')
            elif opt == '\sc':
                self.show_config(type_='active')
            elif opt == '\sau':
                self.update_active_users()
                logging.log(self.user_list)
                print(self.user_list)
            elif opt == '\sf':
                print(Color.WARNING +
                        'WARNING: All users will be disconnected with out any notification!!' +
                        Color.ENDC)
                opt = input('Do you really want to close server?[Y/N] ')
                if opt == 'Y':
                    logging.log('Shuting down server...')
                    print('Shuting down server...')
                    TERMINATE = True
                    sys.exit(0)
                else:
                    logging.log('Aborted.')
                    print('Aborted.')
                    pass
            elif opt == '':
                pass
            else:
                print('COMMAND NOT FOUND!!')

    def init_clients(self):
        global CLI_HASH
        while not TERMINATE:
            try:
                self.server.settimeout(1)
                conn, addr = self.server.accept()
            except socket.timeout:
                pass
            except Exception as e:
                raise e
            else:
                logging.log(
                        'A connection from [{}.{}] has been received.'.format(
                            addr[0], addr[1]))
                cli_obj = Client(conn, addr, self)
                CLI_HASH[conn] = cli_obj

                threading._start_new_thread(cli_obj.run, ('',))
        try:
            print('Server has stopped listening on opened socket.')
            print('Broadcasting connection termination signal..')
            msg = "Sorry! We are unable to serve at this moment."
            for cli_socket in CLI_HASH.keys():
                try:
                    cli_socket.send(msg.encode())
                except:
                    cli_socket.close()
                    CLI_HASH.pop(cli_socket)
        except:
            pass

    def init(self):
        logging.log('Initializing server')
        if len(sys.argv) == 1:
            self.show_config(type_='default')
            opt = input('Set these default config?[Y/n] ')
            if opt == '':
                opt = 'Y'
            if opt in ('Y', 'y', 'yes', 'Yes', 'YES'):
                print("Setting up default configurations...")
            else:
                self.set_usr_config(parameters=False)
        else:
            self.set_usr_config(parameters=True)
    
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
        try:
            self.server.bind((self.HOST_IP, int(self.HOST_PORT)))
            self.server.listen(int(self.MAX_USR_ACCPT))
        except:
            print('Unable to bind HOST IP and PORT.\nPlease check your configuration')            
            sys.exit('EMERGENCY')
        print('\nServer is listening at {}:{}'.format(self.HOST_IP, self.HOST_PORT))
        print('Server is configured to accept %s clients.' %(str(self.MAX_USR_ACCPT)))


        #thread_srv = threading.Thread(target=self.srv_prompt, args=())
        thread_cli = threading.Thread(target=self.init_clients, args=())

        thread_cli.start()
        self.srv_prompt()
        
        for thread in (thread_srv, thread_cli):
            thread.join()
        print('Server and Client threads are exited.')


class Client():
    def __init__(self, conn, addr, srv_obj):
        global PORT
        self.srv_obj = srv_obj
        self.conn = conn
        self.addr = addr
        self.userName = '-N/A-'
        self.PUBLIC_KEY = None
        self.KEY = ''
        self.items_file='result.txt'
        self.port = PORT
        PORT = PORT +1
        self.EnSharedKey =""

    def validate_user(self):
        pass

    def features(self, msg):
        if msg == '@getonline':
            self._loop_break_flag = True
            self.conn.send(
                    AES_.encrypt(self.KEY, str(self.srv_obj.user_list)))
        if msg.split()[0][1:] in self.srv_obj.user_list:
            self._loop_break_flag = True
            for _conn in CLI_HASH:
                if CLI_HASH[_conn].userName == msg.split()[0][1:]:
                    try:
                        self.IND_SOCK = _conn
                        msg_send = "<" + self.userName + "@" + self.addr[0] +\
                                "> [IND] " + ' '.join(msg.split()[1:])
                        self.broadcast(msg_send, IND_FLAG=True)
                    except Exception as e:
                        logging.log(msg_type='EXCEPTION', msg=e)

    def getSharedKey(self):
        TOKEN_CHAR_LIST = "abcdefghij!@#$%"

        # Generate unique symmetric 10bit key for each client
        passphrase = ''.join(random.sample(TOKEN_CHAR_LIST, 10))
        shared_key = hasher(passphrase)
        EnSharedKey = RSA_.encrypt(self.PUBLIC_KEY, shared_key)
        if EnSharedKey:
            return (shared_key, EnSharedKey)
        else:
            logging.log("Unable to encrypt shared key with RSA.", msg_type='ERROR')


    def result(self , *args):
        file = open(self.items_file,"r")
        fileList = file.readlines()
        file.close()
        self.broadcast(fileList)


    def time1 (self):
        self.sock.listen(1)
        flag = 1
        try :
            while True:
                print('waiting for a connection')
                connection, client_address = self.sock.accept()

                try:
                    print('connection from', client_address)

                    while True:
                        data = connection.recv(64)
                        if flag == 1 :
                            self.Token, self.STRTOKEN = pickle.loads(data)
                            if data:
                                if (self.Token == self.KEY and self.STRTOKEN=="TOKEN") :
                                    print("This user is Valid")
                                    flag = 0
                                else:
                                    print("This user is not Valid")
                                    connection.close()
                                    return
                        else :
                            if data.decode()=="bye" :
                                try:
                                    with lock.acquire(timeout=10):
                                        wfile = open(self.items_file, 'w+')
                                        for ilist in ll:
                                            wfile.write(str(ilist) + "\n")
                                        wfile.close()
                                        lock.release()
                                except :
                                    print("Another instance of this application currently holds the lock.")

                            if data :
                                print(str(self.userName)+ " : " + str(data.decode()))
                                ll.append(str(self.userName)+ " : " + str(data.decode()))
                            else:
                                return

                finally:
                    connection.close()
        except :
            "what the fuck ?"

    def time2 (self):
        while True:
            try:
                self._loop_break_flag = False
                msg = self.conn.recv(20000)

                if msg:
                    if msg.split()[0][0] == '@':
                        self.srv_obj.update_active_users()
                        self.features(msg)

                    if not self._loop_break_flag:
                        self.result()
                else:
                    self.remove()
                    pass
            except Exception as e:
                logging.log(msg_type='EXCEPTION', msg='[{}] {}'.format(self.userName, e))

    def run(self, *args):
        data = self.conn.recv(4000)
        if data:
            self.userName, self.PUBLIC_KEY = pickle.loads(data)
        if self.PUBLIC_KEY:
            self.KEY, self.EnSharedKey = self.getSharedKey()
        else:
            tmp_conn = "{}:{}".format(self.addr[0], self.addr[1])
            logging.log(
                    "Public key has not been received from [{}@{}]".format(
                        self.userName, tmp_conn))
            logging.log(
                "[0.0.0.0:8081 --> {}] Socket has been terminated ".format(tmp_conn))
            self.remove()

        if self.KEY == '':
            logging.log("Symmetric key generation failed")

        tmp_msg = "symmetric key {} has been sent to {}".format(self.KEY, self.userName)
        logging.log(tmp_msg)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_hostname = socket.gethostname()
        local_fqdn = socket.getfqdn()
        ip_address = socket.gethostbyname(local_hostname)
        print("working on %s (%s) with %s" % (local_hostname, local_fqdn, ip_address))
        server_address = (ip_address, self.port)
        print('starting up on %s port %s' % server_address)
        self.sock.bind(server_address)

        EnSharedKey = (self.port , self.EnSharedKey)
        EnSharedKey = pickle.dumps(EnSharedKey)
        self.conn.send(EnSharedKey)

        Thread(target=self.time1()).start()
        Thread(target=self.time2()).start()


    def broadcast(self, msg, IND_FLAG=False):
        msg = pickle.dumps(msg)

        if IND_FLAG:
            self.IND_SOCK.send(msg)
            return
        for cli_socket in CLI_HASH.keys():
            if 1==1 :
                try:
                    cli_socket.send(msg)
                except:
                    raise Exception
                    cli_socket.close()
                    self.remove()

    def remove(self):
        if self.conn in CLI_HASH.keys():
            self.conn.close()
            CLI_HASH.pop(self.conn)
            self.srv_obj.update_active_users()
            print(self.srv_obj.user_list)
            sys.exit()

if __name__ == "__main__":
    try:
        logging = Log(f_name='server_chatroom_' + datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
        logging.logging_flag = True
        logging.silent_flag = True
        logging.validate_file()
        server = Server()
        server.init()
    except SystemExit as e:
        if e.code != 'EMERGENCY':
            raise
        else:
            print(sys.exc_info())
            print('Something went wrong!!\nPlease contact developers.')
            os._exit(1)
    except:
        raise Exception
        print('Something went wrong!!\nPlease contact developers\nTerminating the process forcefully..')
        time.sleep(1)
        os._exit(1)
