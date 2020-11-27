#! /usr/bin/env python3
import socket
import pickle
import threading
import time
from datetime import datetime
from tkinter import *
from APIs.logging import Log
from APIs.security import *
from threading import Thread
GUI_OBJ = None
KEY = None


class GUI(object):
    def __init__(self, master, network_obj):
        global GUI_OBJ
        self.master = master
        self.network = network_obj
        self.txt_input = Text(self.master, width=60, height=5)
        self.txt_disp = Text(self.master, width=60, height=15, bg='light grey')
        self.txt_input.bind('<Return>', self.get_entry)
        self.txt_disp.configure(state='disabled')
        self.txt_input.focus()
        self.txt_disp.pack()
        self.txt_input.pack()
        self.flag = True
        GUI_OBJ = self

    def init_canvas(self):
        self.canvas = Canvas(root, width=730, height=600)
        self.canvas.pack(fill="both", expand=True)

    def init_frame(self):
        self.frame_left = Frame(self.canvas, height=400, width=200)
        self.frame_right = Frame(self.canvas, width=500)
        self.frame_right_chat_show = Frame(self.frame_right)
        self.frame_right_chat_input = Frame(self.frame_right, width=460)
        self.frame_right_chat_input_buttons = Frame(self.frame_right, width=40)

        self.frame_left.pack(fill=Y, side='left')
        self.frame_right.pack(fill=Y, side='left')
        self.frame_right_chat_show.pack(fill=X, side='top')
        self.frame_right_chat_input.pack(side='left')
        self.frame_right_chat_input_buttons.pack(side='left')

    def update(self, msg):
        msg = '\n' + msg
        self.txt_disp.configure(state='normal')
        self.txt_disp.insert(END, msg)
        self.txt_disp.see(END)
        self.txt_disp.configure(state='disabled')

    def get_entry(self, *arg):

        msg_snd = self.txt_input.get('1.0', END)
        msg_snd = msg_snd.strip('\n')
        self.network.send_msg(msg_snd)
        #msg_snd = '<YOU> ' + msg_snd
        #self.update(msg_snd)
        self.txt_input.delete('1.0', END)

    def get_msg(self, *arg):
        while True:
            msg_rcv=[]
            msg_rcv = self.network.get_msg()
            x=""
            if msg_rcv:
                try:
                    print(msg_rcv)
                    for i in range(len(msg_rcv)):
                        x=msg_rcv[i][0:].strip('\n')
                        print('-' * 60)
                        print(x)
                        self.update(x)
                except:
                    pass

class Network():
    def __init__(self, thread_name, SRV_IP='', SRV_PORT=''):
        self.SRV_IP = SRV_IP
        self.SRV_PORT = int(SRV_PORT)
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.SRV_IP, self.SRV_PORT))
        self.KEY_FLAG = False
        self.priv_key = None
        self.pub_key = None

    def genRSA(self, *args):
        self.priv_key, self.pub_key = RSA_.genRSA()

    def initialConnection(self,PORT,KEY):
        # create TCP/IP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_hostname = socket.gethostname()
        local_fqdn = socket.getfqdn()
        ip_address = socket.gethostbyname(local_hostname)
        server_address = (ip_address, PORT)
        self.sock.connect(server_address)
        print("connecting to %s (%s) with %s" % (local_hostname, local_fqdn, ip_address))
        msg_token = (KEY, "TOKEN")
        msg_token = pickle.dumps(msg_token)
        self.sock.send(msg_token)
        # define example data to be sent to the server

        while(1==1):
            s=input(" ")
            self.sock.sendall(s.encode())
            if (s=="bye"):
                self.sock.close()
                return


    def initEncryption(self, userName):
        global KEY
        global PORT
        msg_send = (userName, self.pub_key)
        msg_send = pickle.dumps(msg_send)
        self.client.send(msg_send)
        logging.log("User name along with public key has been sent to the server.")
        EnSharedKey = self.client.recv(1024)
        PORT , EnSharedKey  = pickle.loads(EnSharedKey)
        KEY = RSA_.decrypt(self.priv_key, EnSharedKey)

        if KEY:
            logging.log("Unique Token has been received")
            print("TOKEN: " + str(KEY))
            self.KEY_FLAG = True
        if PORT:
            logging.log("Unique Port has been received")
            print("Port: " + str(PORT))
            Thread(target= self.initialConnection(PORT,KEY)).start()

    def get_msg(self):
        if KEY != None:
            #msg_rcv = AES_.decrypt(KEY.encode(), self.client.recv(20000))
            msg_rcv = self.client.recv(20000)
            msg_rcv=pickle.loads(msg_rcv)
            return msg_rcv

    def send_msg(self, msg_snd):
        if KEY is None:
            self.initEncryption(msg_snd)
            return
        try:
            #print(msg_snd)
            #result = self.client.send(AES_.encrypt(KEY.encode(), msg_snd))
            msg_snd=pickle.dumps(msg_snd)
            self.client.send(msg_snd)
        except Exception as e:
            print(e)
            GUI.update(GUI_OBJ, "Not connected to the server")

def connection_thread(*args):
    root = args[0]
    retry_count = 0
    gui_flag = False
    while True:
        try:
            network = Network('network_thread', '127.0.0.1', 8081)
            if gui_flag:
                gui.network = network
            if not gui_flag:
                gui = GUI(root, network)
            logging.log('Connected to the server')
            gui.update('Connected to the server')
            gui.update('Enter your name.')
            break
        except Exception as e:
            msg = "[Retry {}] {}".format(retry_count+1, e)
            logging.log(msg)
            retry_count += 1
            if retry_count == 1:
                gui = GUI(root, None)
                gui.update("Failed to connect the server.\n" +\
                        "Started retrying.")
                gui.update("Retry connecting...")
                time.sleep(5)
                gui_flag = True
            elif 4 > retry_count:
                time.sleep(5)
                gui_flag = True
            elif retry_count == 5:
                gui.update("Retry limit exceeded.\n" +\
                        "Unable to connect the server.\n" +\
                        "Program will automatically exit after 5 sec.")
                time.sleep(5)
                gui_flag = True
                root.destroy()
    rsa_thread = threading.Thread(target=network.genRSA, args=())
    rsa_thread.start()
    rsa_thread.join()
    threading._start_new_thread(gui.get_msg,())

def main():
    root = Tk() # instialize root window
    root.title('PublicChannel')

    threading._start_new_thread(connection_thread, (root,))
    root.mainloop()
    logging.stop()

if __name__ == "__main__":
    logging = Log(f_name='client_publicchannel_' + datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    opt = input('Enable logging? (y/N): ')
    if opt in ('y', 'Y', 'yes', 'Yes', 'YES'):
        logging.logging_flag = True
        logging.validate_file()
    main()