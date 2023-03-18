import socket
import select
import datetime
import time
from tqdm import tqdm
import threading
import hashlib
import random
import os
import requests
import json
import platform
def log(log_str,time_stamp=True):
    try:
        with open('log.txt', 'a+') as f:
            time_stamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if time_stamp:
                log_str += "  " + time_stamp+'\n'
            f.write(log_str)
            f.close()
    except Exception as e:
        print("保存日志出错:{} {}".format(e,log_str))

def get_environment_info():
    host_name = platform.node()
    os_type = platform.system()
    os_version = platform.release()
    return "Host name: {} Operating System: {} {}".format(host_name, os_type, os_version)

def get_ipv4_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

def get_public_ipv4_address():
    response = requests.get("http://checkip.amazonaws.com/")
    return response.text.strip()

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
                
def generate_hash(file_path):
    hash_code = hashlib.sha224()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_code.update(chunk)
    return hash_code.hexdigest()

def classify_file(file_name,source):
    file_type = None
    name, ext = os.path.splitext(file_name)
    if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
        file_type = "img"
    else:
        file_type = "file"
    return json.dumps({"source":source, "file_type": file_type, "file_name": file_name})
def file_type(file_name):
    _, ext = os.path.splitext(file_name)
    return "img" if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'] else "file"

def get_file_info(directory):
    files = os.listdir(directory)
    file_list = []
    img_list = []
    for f in files:
        path = os.path.join(directory, f)
        if os.path.isfile(path):
            size = os.path.getsize(path)
            if size < 1024:
                size_str = f"{size}B"
            elif size < 1024 * 1024:
                size_str = f"{size / 1024:.2f}KB"
            elif size < 1024 * 1024 * 1024:
                size_str = f"{size / 1024 / 1024:.2f}MB"
            else:
                size_str = f"{size / 1024 / 1024 / 1024:.2f}GB"

            if file_type(f) == "file":
                file_list.append((f, size, size_str))
            else:
                img_list.append((f, size, size_str))
    if len(file_list) == 0 and len(img_list) == 0:
        result='云盘里什么都没有......'
    else:    
        file_list = sorted(file_list, key=lambda x: x[1], reverse=True)
        result = "\n".join([f"{i + 1}. {filename} {size_str}" for i, (filename, size, size_str) in enumerate(file_list)])
        img_list = sorted(img_list, key=lambda x: x[1], reverse=True)
        result += "\n∎∎∎∎∎∎∎∎以下为图片文件∎∎∎∎∎∎∎∎\n" + "\n".join([f"{i + 1}. {filename} {size_str}" for i, (filename, size, size_str) in enumerate(img_list)])
    return result

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setblocking(False)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(5)
        self.inputs = [self.server]
        self.outputs = []
        self.clients_infomation={}
        self.Chat_history = []
        print(get_environment_info())
        log(get_environment_info())
    def start(self):
        print(f"Server starts listening on {self.host}:{self.port}")
        log(f"Server starts listening on {self.host}:{self.port}")
        while True:
            #print(self.inputs)
            readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)#将所有套接字传入select
            for sock in readable:
                if sock == self.server:
                    client, client_address = self.server.accept()#接受套接字和客户端IP端口信息
                    print(f"Accepted new connection from {client_address[0]}:{client_address[1]}")
                    log(f"Accepted new connection from {client_address[0]}:{client_address[1]}")
                    client.setblocking(False)#设置非阻塞模式
                    self.inputs.append(client)#保存套接字
                    self.outputs.append(client)
                    #self.clients[client] = client_address
                    self.clients_infomation[client] = {'IP':client_address[0],
                                                       'Port':client_address[1],
                                                       'Login':False,
                                                       'Name':''}
                    self.send_one(client,'请先输入您的聊天昵称：')
                else:
                    #try:
                    if sock is None:
                        continue
                    else:
                        try:
                            data = sock.recv(4096)
                            if not data:
                                raise ConnectionAbortedError
                        except ConnectionAbortedError:
                            print("ConnectionAbortedError: The connection has been terminated.")
                            log(f"用户{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}在接收数据时出现异常ConnectionAbortedError: The connection has been terminated.")
                            self.disconnect(sock)
                            continue
                        except Exception as e:
                            print("An unexpected error occurred: ", e)
                            log(f"用户{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}在接收数据时出现异常{e}")
                            self.disconnect(sock)
                            continue
                        finally:
                            # Close the socket and any other resources
                            #continue
                            pass

                        #data = sock.recv(4096)
                        if data != '':
                            print(f"Received data from {self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}: {data.decode()}")
                            log(f"Received data from {self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}: {data.decode()}")
                            if self.clients_infomation[sock]['Login'] == False:
                                self.clients_infomation[sock]['Name'] = data.decode()
                                self.clients_infomation[sock]['Login'] = True
                                self.broadcast('[{}]进入了聊天室，目前在线：{} 人'.format(data.decode(),len(self.clients_infomation))+self.current_time(),None)
                                thread = threading.Thread(target=self.Send_history, args=(None,sock))
                                print("开始发送聊天记录")
                                log(f"开始向{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}发送聊天记录")
                                thread.start()
                            else:
                                message='[{}]'.format(self.clients_infomation[sock]['Name'])+data.decode()+self.current_time()
                                if self.parse_command(data.decode(),sock):
                                    log(f'执行指令 {message}',False)
                                    pass
                                else:
                                    self.broadcast(message,None)
                        else:
                            self.disconnect(sock)
                    """
                    except ConnectionResetError:
                        log(f"用户{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}在接收数据时出现异常")
                        self.disconnect(sock)
                    except ConnectionAbortedError as e:
                        print("Connection aborted by peer:", e)
                        self.disconnect(sock)
                    except Exception as e:
                        self.disconnect(sock)
                        print("Other exception:", e)
                    """
            for sock in exceptional:
                log(f"用户{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}被select判定为连接异常")
                self.disconnect(sock)
    def Send_history(self,none,sock):
        self.send_one(sock,'以下是历史聊天记录...')
        for message in self.Chat_history:
            if message.startswith('!展示文件'):
                time.sleep(1)
            else :
                time.sleep(0.1)
            self.send_one(sock,message)
        self.send_one(sock,'聊天记录接收完毕')
    def disconnect(self,sock):
        message=f"[{self.clients_infomation[sock]['Name']}]下线了，目前在线：{len(self.clients_infomation)-1} 人"+self.current_time()
        print(f"Client {self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']} disconnected")
        log(f"Client {self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']} disconnected")
        self.inputs.remove(sock)
        self.outputs.remove(sock)
        sock.close()
        del self.clients_infomation[sock]
        time.sleep(0.5)
        self.broadcast(message,None)
    def broadcast(self,message,none):
        log(f'广播 {message}')
        while True:
            if len(self.Chat_history)>10:
                del self.Chat_history[0]
            else:
                break
        self.Chat_history.append(message)
        for client in self.clients_infomation:
            if self.clients_infomation[client]['Login']:
                self.send_one(client,message)
            else:
                pass
    def send_one(self,client,message):
        try:
            message=bytes(message,encoding='utf8')
            if client is None:
                return False
            else:
                client.sendall(message)
                return True
        except Exception as e:
            log(f"用户{self.clients_infomation[client]['IP']}:{self.clients_infomation[client]['Port']}在发送数据时出现异常:{e}")
            print(f"发送时出现异常:{e}")
            self.disconnect(client)
            return False

    def current_time(self):
        now = datetime.datetime.now()
        return now.strftime(" (%Y-%m-%d %H:%M:%S)")
    def parse_command(self,cmd_str,sock):
        commands = {
            "查询天气" : self.query_weather,
            "搜索" : self.search,
            "上传文件":self.recv_file,
            "查看文件":self.cloud,
            "下载文件":self.send_file,
        }
        if not cmd_str.startswith("！"):
            return False
        cmd = cmd_str[1:]
        cmd = cmd.split('*')
        if cmd[0] in commands:
            commands[cmd[0]](cmd[1:],sock)
            return True
        return False
    def search(self,things,sock):
        # 这里实现搜索的逻辑
        print("搜索")
    def query_weather(self,location,sock):
        # 这里实现查询天气的逻辑
        print("查询天气")
    def recv_file(self,file_info,sock):
        '''
        file_info=[文件路径*文件大小*文件哈希码]
        '''
        HOST = self.host
        PORT = get_random_port()
        NAME = file_info[0].split('/')[-1]
        Command='!发送文件*{}*{}*{}'.format(HOST,PORT,file_info[0])
        if self.send_one(sock,Command):
            log(f"Send [{Command}] to {self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}")
            os.makedirs('./Cloud', mode=0o777, exist_ok=True)
            thread = threading.Thread(target=self.start_recv_server, args=(HOST, PORT, 
                                    './Cloud/'+NAME, float(file_info[1]), sock, file_info[2]))
            print("开始传输文件")
            log(f"开始接收{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}传来的文件:{NAME}")
            thread.start()
        else :
            log(f"让客户端{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}发送文件的指令发送失败")
            print('客户端已主动断开连接')
            
    def start_recv_server(self, ip, port, file_name, file_size, sock, hash_code):
        # Create a new thread
        thread = threading.Thread(target=self.receive_file, args=(ip, port, file_name, file_size))
        thread.start()
        thread.join()
        if os.path.exists(file_name):
            HASH=generate_hash(file_name)
            if hash_code==HASH :
                message = '文件 {} 已上传成功！'.format(file_name)
                try :
                    sock.sendall(bytes(message,encoding='utf8'))
                except Exception as e:
                    log(f"向{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}发送信息失败 {e}")
                    print(f'客户端断联 {e}')
                    self.disconnect(sock)
                log(message)
                message="!展示文件*"+classify_file(file_name.split('/')[-1],self.clients_infomation[sock]['Name'])
                print(message)
                self.broadcast(message,None)
            else:
                message = '文件 {} 哈希校验出错，请重新上传该文件！'.format(file_name)
                try :
                    sock.sendall(bytes(message,encoding='utf8'))
                except Exception as e:
                    print('客户端断联 {}'.format(e))
                    log(f"向{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}发送信息失败 {e}")
                    self.disconnect(sock)
                log(message)
                os.remove(file_name)
                log(f'已删除文件 {file_name}')
        else:
            message = '文件 {} 未上传成功，请重新上传该文件！'.format(file_name)
            try :
                sock.sendall(bytes(message,encoding='utf8'))
            except Exception as e:
                print('客户端断联 {}'.format(e))
                log(f"向{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}发送信息失败 {e}")
                self.disconnect(sock)
            log(message)
            
    def receive_file(self, ip, port, file_name, file_size):
        try:
            # Create a TCP socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(5.0)
            server_socket.bind((ip, port))
            server_socket.listen(1)
                # Accept a single connection
            try:
                conn, addr = server_socket.accept()
                print(f"Connected by {addr}")
            except socket.timeout:
                print('Listening time out!')
                log('文件接收服务器监听超时')
                server_socket.close()
                return False
            except Exception as e:
                print('监听时出现异常 {}'.format(e))
                log(f'文件接收服务器监听异常 {e}')
                server_socket.close()
                return False
            conn.settimeout(5.0)
            # Receive the file
            buffer = b''
            # Show the progress bar using tqdm library
            with tqdm(total=file_size/1024, unit='KB', unit_scale=True, unit_divisor=1024, desc=file_name, ascii=True) as pbar:
                while True:
                    try:
                        data = conn.recv(4096)
                    except socket.timeout:
                        print('Recv time out!')
                        log('文件接收超时')
                        conn.close()
                        return False
                    except Exception as e:
                        print('文件接收时出现异常 {}'.format(e))
                        conn.close()
                        log(f'文件接收异常 {e}')
                        return False
                    if not data:
                        break
                    buffer += data
                    pbar.update(len(data)/1024)

            # Write the file to disk
            with open(file_name, 'wb') as f:
                f.write(buffer)
            # Close the connection and the socket
            conn.close()
            server_socket.close()
            print('File saved in {}'.format(file_name))
            log('File saved in {}'.format(file_name))
            return True
        except Exception as e:
            print(f"An error occurred: {e}")
            log(f'接收客户端上传文件时出错:{e}')
            return False
    
    def cloud(self,info,sock):
        os.makedirs('./Cloud', mode=0o777, exist_ok=True)
        self.send_one(sock,'云盘中有如下文件：\n'+get_file_info('./Cloud'))
        
    def send_file(self,server_info,sock):
        #info=[FileName]
        file_path = './Cloud/'+server_info[0]
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            hash_code = generate_hash(file_path)
            HOST = self.host
            PORT = get_random_port()
            NAME = server_info[0].split('/')[-1]
            Command='!接收文件*{}*{}*{}*{}*{}'.format(HOST,PORT,server_info[0],hash_code,file_size)
            #[IP*端口*文件名*文件哈希码*文件大小
            if self.send_one(sock,Command): 
                log(f"Send [{Command}] to {self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}")
                thread = threading.Thread(target=self.start_send_server, args=(HOST, PORT, 
                                   file_path, hash_code, file_size, sock))
                print("开始传输文件")
                thread.start()
            else :
                log(f"让客户端{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}接收文件的指令发送失败")
                print('客户端已主动断开连接')
        else:
            self.send_one(sock ,'文件 {} 不存在！'.format(server_info[0]))
            log('文件 {} 不存在！'.format(server_info[0]))
    def start_send_server(self, ip, port, file_name, hash_code, file_size, sock):
        try:
            # Create a TCP socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5.0)
            client_socket.bind((ip, port))
            client_socket.listen(1)
            try:
                conn, addr = client_socket.accept()
                print(f"Connected by {addr}")
            except socket.timeout:
                log(f"客户端{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}下载文件时监听超时")
                print('Listening time out!')
                client_socket.close()
                return False
            except Exception as e:
                print('监听时异常 {}'.format(e))
                log(f"客户端{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}下载文件时监听异常 {e}")
                client_socket.close()
                return False
            conn.settimeout(5.0)

            # Open the file to be sent
            with open(file_name, 'rb') as f:
                # Show the progress bar using tqdm library
                with tqdm(total=file_size/1024, unit='KB', unit_scale=True, unit_divisor=1024, desc=file_name, ascii=True) as pbar:
                    while True:
                        chunk = f.read(4096)
                        if not chunk:
                            conn.close()
                            client_socket.close()
                            #log(f"客户端{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}下载文件时读取缓冲区为空")
                            break
                        try:
                            conn.sendall(chunk)
                            pbar.update(len(chunk)/1024)
                        except ConnectionResetError:
                            conn.close()
                            client_socket.close()
                            log(f"客户端{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}下载文件时连接中断")
                            print('Connection Error!')
                            return False
                        except Exception as e:
                            print('下载文件发送时异常 {}'.format(e))
                            conn.close()
                            client_socket.close()
                            log(f"客户端{self.clients_infomation[sock]['IP']}:{self.clients_infomation[sock]['Port']}下载文件时异常 {e}")
                            return False
                    pbar.close()
                f.close()
            # Close the socket
            conn.close()
            client_socket.close()
            print('File sent to {}:{}'.format(ip, port))
            log('File sent to {}:{}'.format(ip, port))
            return True
        except Exception as e:
            print(f"An error occurred: {e}")
            log(f'客户端下载文件时出错：{e}')
            return False
if __name__ == "__main__":
    Port=510
    server = Server(get_ipv4_address(), Port)#get_random_port())
    server.start()