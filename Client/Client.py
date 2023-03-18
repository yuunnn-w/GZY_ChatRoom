import socket
from mttkinter import mtTkinter as tk
import tkinter.scrolledtext as tkst
import threading
from tkinter import filedialog
import hashlib
import time
import os
from tqdm import tqdm
import random
from PIL import Image, ImageTk
import json
import errno

def get_random_port():
    while True:
        # Generate a random port number between 1025 and 65535
        port = random.randint(1025, 65535)

        # Check if the port is available
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("", port))
                return port
            except OSError:
                continue
                
def get_ipv4_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

def generate_hash(file_path):
    hash_code = hashlib.sha224()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_code.update(chunk)
    return hash_code.hexdigest()

def get_file_size(path):
    size_in_bytes = os.path.getsize(path)
    print('[{}] : {:.2f} KB / {:.2f} MB / {:.2f} GB'.format(path.split('/')[-1],size_in_bytes / 1024,size_in_bytes / (1024 ** 2),size_in_bytes / (1024 ** 3)))
    return size_in_bytes


def map_image_size(file_name):
    image = Image.open(file_name)
    width, height = image.size
    min_size = min(width, height)
    if min_size < 64:
        ratio = 64 / min_size
        size = (int(width * ratio), int(height * ratio))
    elif min_size > 200:
        ratio = 200 / min_size
        size = (int(width * ratio), int(height * ratio))
    else:
        size = (width, height)
    image = image.resize(size)
    return image


class ClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("关注顾子韵_w喵,关注阿梓从小就很可爱谢谢喵~")
        self.ip_label = tk.Label(master,text="IP")
        self.ip_label.grid(row=0, column=0)
        self.ip_entry = tk.Entry(master)
        self.ip_entry.grid(row=0, column=1,columnspan=2)

        self.port_label = tk.Label(master, text="Port")
        self.port_label.grid(row=1, column=0)
        self.port_entry = tk.Entry(master)
        self.port_entry.grid(row=1, column=1,columnspan=2)

        self.connect_button = tk.Button(master, text="Connect", command=self.connect)
        self.connect_button.grid(row=2, column=0)
        self.disconnect_button = tk.Button(master, text="Disconnect", command=self.disconnect, state=tk.DISABLED)
        self.disconnect_button.grid(row=2, column=1)
        
        self.scrollbar = tk.Scrollbar(master)
        self.scrollbar.grid(row=3, column=3, sticky='nsew')
        
        self.received_data = tk.Text(master, height=20, width=60,state=tk.DISABLED,yscrollcommand=self.scrollbar.set)
        self.received_data.grid(row=3, column=0, columnspan=3, sticky="nsew")
        self.received_data.tag_config("Name", background="pink", foreground="black")
        self.received_data.tag_config("Warning", background="yellow", foreground="red")
        self.received_data.tag_config("Attention", background="aquamarine", foreground="black")
        self.scrollbar.config(command=self.received_data.yview)
        
        #self.input_text = tk.Entry(master, state=tk.DISABLED)
        #self.input_text.grid(row=4, column=0, sticky="nsew")
        self.input_text = tkst.ScrolledText(master, height=2, width=60, state=tk.DISABLED)
        self.input_text.grid(row=4, column=0,columnspan=2, sticky="nsew")
        #self.input_text.bind('<Return>', self.Return)
        
        self.switch_var = tk.IntVar()
        self.switch = tk.Checkbutton(root, text="回车发送", variable=self.switch_var)
        self.switch.grid(row=2, column=2, sticky="nsew")
        self.switch.config(command=self.Return)
        
        #self.input_text.bind('<Return>', lambda event: None)
        self.send_button = tk.Button(master, text="Send", state=tk.DISABLED, command=self.send_message)
        self.send_button.grid(row=4, column=2, sticky="nsew")
        
        self.send_file_button = tk.Button(master, text="File", state=tk.DISABLED, command=self.select_file)
        self.send_file_button.grid(row=4, column=3, sticky="nsew")
        
        master.columnconfigure(0, weight=1)
        master.columnconfigure(1, weight=1)
        master.rowconfigure(3, weight=1)
        master.rowconfigure(4, weight=0)
        
        self.file_path=''#待发送的文件路径
        self.statement = False
        self.download = 'init'
        
        self.images = []

        
    def Print(self,Message,Type='Normal'):
        if Type=='Normal':
            self.received_data.config(state=tk.NORMAL)
            self.received_data.insert(tk.END, Message)
            self.received_data.insert(tk.END, "\n")
            self.received_data.see('end')
            self.received_data.config(state=tk.DISABLED)
        else:
            self.received_data.config(state=tk.NORMAL)
            self.received_data.insert(tk.END, Message,Type)
            self.received_data.insert(tk.END, "\n")
            self.received_data.see('end')
            self.received_data.config(state=tk.DISABLED)
    def Return(self):
        if self.switch_var.get():
            self.input_text.bind('<Return>', self.send_message)
        else:
            self.input_text.bind('<Return>', lambda event: None)
        return
    def connect(self):
        ip = self.ip_entry.get()
        port = int(self.port_entry.get())
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #self.client.settimeout(3)
            try:
                self.client.connect((ip, port))
            except socket.timeout:
                self.Print(Message='Connecting time out!',Type='Warning')
                self.client.close()
                return
            self.connect_button.config(state=tk.DISABLED)
            self.disconnect_button.config(state=tk.NORMAL)
            self.input_text.config(state=tk.NORMAL)
            self.send_button.config(state=tk.NORMAL)
            self.send_file_button.config(state=tk.NORMAL)
            self.Print(Message='Connect successfully',Type='Attention')
            
            thread = threading.Thread(target=self.receive_data)
            thread.start()
            self.statement = True
        except:
            self.Print(Message="Error: Server is unavailable",Type='Warning')
    def receive_data(self):
        start_time = time.time()
        #self.client.settimeout(3)
        self.client.setblocking(0)
        closed = False
        while not closed:
            elapsed_time = time.time() - start_time
            if elapsed_time > 600: # 10 minutes in seconds
                print('超时退出')
                self.Print(Message="长时间未接收到服务器消息，请重新连接服务器！",Type='Warning')
                closed = True
                break
            try:
                if self.client is None:
                    print("Peer closed connection")
                    closed = True
                    break
                else :
                    data = self.client.recv(4096).decode('utf-8')
                if data:
                    # 处理接收到的数据
                    print("Received data:", data)
                    start_time = time.time()
                    if self.parse_command(data) :
                        pass
                    else:
                        s=data.find('[')
                        f=data.find(']')
                        if s!=-1 and f != -1:
                            Name=data[s:f+1]
                            message=data[f+1:]
                            self.received_data.config(state=tk.NORMAL)
                            self.received_data.insert(tk.END, Name ,'Name')
                            self.received_data.insert(tk.END, ' '+message + '\n')
                            self.received_data.see('end')
                            self.received_data.config(state=tk.DISABLED)
                        else:
                            self.Print(Message=data)
                else:
                    #未接收到数据
                    continue
            except socket.error as e:
                if e.errno == errno.EAGAIN or e.errno == errno.EWOULDBLOCK:
                    # 没有接收到数据，需要等待下次再试
                    continue
                elif e.errno == errno.ENOTSOCK:
                    # 套接字已关闭
                    print("Socket closed")
                    closed = True
                    break
                else:
                    # 处理其他错误
                    print("Socket error:", e)
                    closed = True
                    break
        self.Print(Message="Lost connection to the server",Type='Warning')
        self.disconnect()
        return
    def disconnect(self):
        try:
            self.client.close()
            self.connect_button.config(state=tk.NORMAL)
            self.disconnect_button.config(state=tk.DISABLED)
            self.input_text.config(state=tk.DISABLED)
            self.send_button.config(state=tk.DISABLED)
            self.send_file_button.config(state=tk.DISABLED)
            self.statement = False
        except Exception as e:
            print('断开连接时异常 {}'.format(e))
            
    def send_message(self, event=None):
        message = self.input_text.get("1.0","end").strip()
        self.input_text.delete("1.0","end")
        print('准备发送：[{}]'.format(message))
        if self.Command(message):
            pass
        else:
            try:
                self.client.sendall(message.encode('utf-8'))
                self.client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except:
                self.Print(Message="Error: message not sent",Type='Warning')
                self.Print(Message="Lost connection to the server",Type='Warning')
                self.disconnect()
    def parse_command(self,cmd_str):
        commands = {
            "发送文件" : self.send_file,
            "接收文件" : self.recv_file,
            "展示文件" : self.show_file,
        }
        if not cmd_str.startswith("!"):
            return False
        cmd = cmd_str[1:]
        cmd = cmd.split('*')
        if cmd[0] in commands:
            commands[cmd[0]](cmd[1:])
            return True
        return False
    def Command(self,cmd_str):
        commands = {
            "下载文件" : self.download_file,
        }
        if not cmd_str.startswith("！"):
            return False
        cmd = cmd_str[1:]
        cmd = cmd.split('*')
        if cmd[0] in commands:
            commands[cmd[0]](cmd[1:])
            return True
        return False
    def Read_file(self,file_path):
        pass
    def select_file(self):
        if self.file_path != '':
            self.Print(Message='当前文件 {} 正在发送中，请稍后...'.format(self.file_path),Type='Warning')
        else:
            self.file_path = filedialog.askopenfilename()
            size = get_file_size(self.file_path)
            file_name = self.file_path.split('/')[-1]
            hash_code = generate_hash(self.file_path)
            Command = '！上传文件*{}*{}*{}'.format(self.file_path,size,hash_code)
            try:
                self.client.sendall(Command.encode())
                self.Print(Message="开始传输文件 {}".format(file_name))
                self.file_path = '' 
            except:
                self.Print(Message="Error: 文件传输失败！",Type='Warning')
                self.file_path = ''
                self.Print(Message="Lost connection to the server",Type='Warning')
                self.disconnect()
    def send_file(self,server_info):
        server_ip = self.ip_entry.get()
        server_port = int(server_info[1])
        file_path = server_info[2]
        self.Print(Message="正在上传 {}......".format(file_path))
        thread = threading.Thread(target=self.Send_File_, args=(file_path, server_ip, server_port))
        thread.start()
    def download_file(self,file_info):
        Command='！下载文件*{}'.format(file_info[0])
        try:
            self.client.sendall(Command.encode())
        except:
            self.Print(Message="Error: message not sent",Type='Warning')
            self.Print(Message="Lost connection to the server",Type='Warning')
            self.disconnect()
    def Send_File_(self,file_path, server_ip, server_port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)
                try:
                    s.connect((server_ip, server_port))
                except socket.timeout:
                    print("Connection to the server timed out.")
                    self.Print(Message="连接服务器超时",Type='Warning')
                    self.file_path = ''
                    s.close()
                    return False
                with open(file_path, 'rb') as f:
                    file_size = os.path.getsize(file_path)
                    pbar = tqdm(total=file_size/1024, unit='KB', unit_scale=True)
                    while self.statement:
                        chunk = f.read(4096)
                        if not chunk:
                            s.close()
                            break
                        try:
                            s.sendall(chunk)
                            pbar.update(len(chunk)/1024)
                        except ConnectionResetError:
                            s.close()
                            print('Connection Error!')
                            self.file_path = ''
                            return False
                    pbar.close()
        except Exception as e:
            print(f"An error occurred: {e}")
            self.file_path = ''
            return False
        self.file_path = ''
        return True
    
    def recv_file(self,file_info):
        '''
        file_info=[IP*端口*文件名*文件哈希码*文件大小
        '''
        HOST=self.ip_entry.get()
        PORT=int(file_info[1])
        File_name=file_info[2]
        hash_code=file_info[3]
        file_size=int(file_info[4])
        #if self.send_one(sock,Command):
        os.makedirs('./Recv', mode=0o777, exist_ok=True)
        thread = threading.Thread(target=self.start_recv_client, args=(HOST, PORT, 
                                    './Recv/'+File_name, file_size,hash_code))
        self.Print(Message="收到服务器指令，开始下载文件...")
        thread.start()
        
    def start_recv_client(self,ip, port, file_name, file_size, hash_code):
        # Create a new thread
        thread = threading.Thread(target=self.Recv_File_, args=(ip, port, file_name, file_size))
        thread.start()
        thread.join()
        if os.path.exists(file_name):
            HASH=generate_hash(file_name)
            if hash_code==HASH :
                message='文件 {} 已下载成功！'.format(file_name)
                if self.download.split('*')[0] == 'Get_img':
                    message='[{}] 发来图片 【{}】'.format(self.download.split('*')[1],file_name.split('/')[-1])
                    self.Print(Message=message,Type='Attention')
                    self.display_image(file_name)
                    self.download = 'init'
                else:
                    self.Print(Message=message,Type='Attention')
            else:
                message='文件 {} 哈希校验出错，请重新下载文件！'.format(file_name)
                self.Print(Message=message,Type='Warning')
                os.remove(file_name)
        else:
            message='文件 {} 未下载成功，请重新下载该文件！'.format(file_name)
            self.Print(Message=message,Type='Warning')
    def Recv_File_(self, server_ip, server_port, file_path, file_size):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)
                try:
                    s.connect((server_ip, server_port))
                except socket.timeout:
                    print("Connection to the server timed out.")
                    self.Print(Message="连接服务器超时",Type='Warning')
                    self.file_path = ''
                    s.close()
                    return False
                # Receive the file
                buffer = b''
                # Show the progress bar using tqdm library
                with tqdm(total=file_size/1024, unit='KB', unit_scale=True, unit_divisor=1024, desc=file_path, ascii=True) as pbar:
                    while True:
                        try:
                            data = s.recv(4096)
                        except socket.timeout:
                            print('Recv time out!')
                            self.file_path = ''
                            s.close()
                            return False
                        if not data:
                            break
                        buffer += data
                        pbar.update(len(data)/1024)

                # Write the file to disk
                with open(file_path, 'wb') as f:
                    f.write(buffer)
                # Close the connection and the socket
                s.close()
                self.file_path = ''
                return True
        except Exception as e:
            print(f"An error occurred: {e}")
            self.file_path = ''
            return False
        self.file_path = ''
        return True
    def show_file(self,info):
        info=json.loads(info[0])
        print(info)
        if info['file_type']=='file':
            message='[{}] 已上传文件【{}】至云端。'.format(info['source'],info['file_name'])
            self.Print(Message=message,Type='Attention')
        else:
            if os.path.exists('./Recv/'+info['file_name']):
                message='[{}] 发来图片 【{}】'.format(info['source'],info['file_name'])
                self.Print(Message=message,Type='Attention')
                self.display_image('./Recv/'+info['file_name'])
            else:
                self.download_file([info['file_name']])
                self.download = 'Get_img*{}'.format(info['source'])
    def display_image(self, file_name):
        image = map_image_size(file_name)
        img_tk = ImageTk.PhotoImage(image)
        if len(self.images) >= 50:
            del self.images[0]
        self.images.append(img_tk)
        self.received_data.config(state=tk.NORMAL)
        self.received_data.image_create(tk.END, image=img_tk)
        self.received_data.insert(tk.END, "\n")
        self.received_data.insert(tk.END, "\n")
        self.received_data.see('end')
        self.received_data.config(state=tk.DISABLED)
        
if __name__ == '__main__':
    root = tk.Tk()
    root.geometry("600x400")
    my_gui = ClientGUI(root)
    root.mainloop()