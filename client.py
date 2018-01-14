#!/sur/bin/env
#-*-coding:utf-8 -*-
#两个对象，一个监听本地的服务器对象，一个连接server的客户端对象
import threading
import socket
import select
import struct
import sys

def send_data(sock, data):
	print(data)
	bytes_sent = 0
	while True:
		r = sock.send(data[bytes_sent:])
		if r < 0:
			return r
		bytes_sent += r
		if bytes_sent == len(data):
			return bytes_sent

def handle(sock,local_client):
	fdset=[sock,local_client]
	try:
		while True:
			r,w,e=select.select(fdset,[],[])
			if sock in r:
				print('sock start')
				data=sock.recv(4096)
				if len(data)<=0:
					print('data:',len(data))
					break
				print('sock recv:',data)
				'''if len(data)<=0:
					break'''
				print('test1!')
				sends=send_data(local_client,data)
			if local_client in r:
				print('local_client start')
				data=local_client.recv(4096)
				if len(data)<=0:
					break
				print('local_client recv:',data)
				sends=sock.sendall(data)
	except socket.error as e:
		sock.close()
		local_client.close()
		print('handle error!\nE:%s'%e)
	finally:
		sock.close()
		local_client.close()
		print('close end!')
		
def wait_accept(socks,server_local):#socks指accept的，local_client指连接到server的socket
		try:
			while(True):
				sock,addr=socks.accept()
				print(addr)
				local_client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
				local_client.connect(server_local.addr)
				if sock:
					t=threading.Thread(target=handle,args=(sock,local_client))
					t.start()
					
		except:
			local_client.close()
			print('wait_accept error!')


class client_Local(object):
	def __init__(self):
		try:
			self.local_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			self.local_socket.bind(('127.0.0.1',80))
			self.local_socket.listen(1024)
			self.local_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		except:
			print('client_Local error!\n')
			sys.exit(0)
	


class server_Local(object):

	def __init__(self):
		self.server_ip=input('please input the server ip:')
		self.server_port=input('Please input the server port:')
		self.addr=(self.server_ip,int(self.server_port))
		print(self.addr)
		
	
	def handle_con(self):
		try:
			self.server_socket.send(b"\x05\x01\x00")
			self.server_socket.recv(256)
			reply=b"\x05\x01\x00\x01"
			reply+=socket.inet_aton(self.server_ip)+struct.pack(">H",int(self.server_port))
			self.server_socket.send(reply)
		except:
			print('error!')
			sys.exit(0)
	def connect_server(self):
		self.server_socket.connect(self.addr)

def main():
	client_local=client_Local()
	server_local=server_Local()
	#server_local.handle_con()
	wait_accept(client_local.local_socket,server_local)
	
	
main()

