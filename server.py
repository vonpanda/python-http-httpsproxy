#!/usr/bin/env
#-*-coding:utf-8-*-

import socket
import sys
import select
import threading
import struct
import re
from urllib.parse import urlparse

rechr_header=r'^(\w+)\s(\S+)\s(\S+)$'
rechr_host=r'Host:\s(\S+)[\r\n]*'
rechr_port=r'^(\S+):(\S+)$'

def do_connect(hosts,port,remote):
	try:
		s=socket.getaddrinfo(hosts,None)
		remote.close()
		remote=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		remote.connect((s[0][4],port))
	except socket.error as e:
		print('connect error:',e)

def get_host(data):
	data=data.decode('utf-8','ignore')
	if data.find('Host:')>0:
		hosts=data[data.find('Host:'):]
	hosts=hosts.replace(': ','')
	hosts=hosts.replace(hosts[hosts.find('\r\n'):],'')
	print('get_host_hosts:',hosts)
	return hosts
	
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
			
def http_handle_tcp(sock,remote,hosts):
	fd_set=[sock,remote]
	try:
		while True:
			r,w,b=select.select(fd_set,[],[])
			if sock in r:
				data=sock.recv(4096)
				
				hosts_re=get_host(data)
				if len(hosts_re>0):
					if hosts_re.find(':')!=-1:
						port=int(hosts_re[hosts_re.find(':')+1:])
						no_port_host=hosts_re.replace(str(port),'')
					else:
						port=80
						no_port_host=hosts_re
					if hosts_re!=hosts:
						do_connect(no_port_host,port,remote)
					print('recv.sock:',data)
				if len(data)<=0:
					break
				result=send_data(remote,data)
				if result<len(data):
					raise Exception('sends<len(data)')
					
			if remote in r:
				data=remote.recv(4096)
				print('remote.sock:',data)
				if len(data)<=0:
					break
				result=send_data(sock,data)
				if result<len(data):
					raise Exception('sends<len(data)')
	except socket.error as e:
		print(' handle_tcp error!\nE:%s'%e)
	
			
def handle_tcp(sock,remote):
	fd_set=[sock,remote]
	try:
		while True:
			r,w,b=select.select(fd_set,[],[])
			if sock in r:
				data=sock.recv(4096)
				hosts_re=get_host(data)
				print('recv.sock:',data)
				if len(data)<=0:
					break
				result=send_data(remote,data)
				if result<len(data):
					raise Exception('sends<len(data)')
					
			if remote in r:
				data=remote.recv(4096)
				print('remote.sock:',data)
				if len(data)<=0:
					break
				result=send_data(sock,data)
				if result<len(data):
					raise Exception('sends<len(data)')
	except socket.error as e:
		print(' handle_tcp error!\nE:%s'%e)
	
		
def handle(sock,addr):
		remote=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		try:
			data=sock.recv(4096)
			data=data.decode('utf-8')
			print('data:',data.encode())
			headers=re.match(rechr_header,data[:data.find('\r\n')])
			hosts=data[data.find('Host'):]
			hosts=re.match(rechr_host,hosts)
			
			if headers.groups()[1].find('http:')>=0 or headers.groups()[1].find('HTTP:')>=0 or hosts.groups()[0].find(':80')>=0:
				print('if:',headers.groups()[1].find('http:'),headers.groups()[1].find('HTTP:'),hosts.groups()[0].find(':80'))
				print(hosts.groups())
				print(headers.groups())
				
				if hosts.groups()[0].find(':')>0:
					print(hosts.groups()[0])
					re_port=re.match(rechr_port,hosts.groups()[0])
					print('re_port:',re_port.groups())
					ports=int(re_port.groups()[1])
					no_port_hosts=hosts.groups()[0].replace(':'+str(ports),'')
					
				else:
					ports=80
					no_port_hosts=hosts.groups()[0]
				
				
				print(no_port_hosts)
				re_place_str='http://'+no_port_hosts
				data_test=headers.groups()[0]+headers.groups()[1].replace(no_port_hosts,'')+headers.groups()[2]+data[data.find('\r\n'):]
				data=data.encode()
				print('http data:',data)
				addr_remote=socket.getaddrinfo(no_port_hosts,ports)
				addr_re=(addr_remote[0][4][0],ports)
				print('http addr_re:',addr_remote[0][4])
				try:
					remote.connect(addr_remote[0][4])
				except socket.error as e:
					remote.close()
					sock.close()
					print('http:remote.connect error!\n:%s'%e)
					return 0
				finally:
					print('addr_re:',addr_re)
				send_data(remote,data)

				http_handle_tcp(sock,remote,hosts.groups()[0])
				
			elif headers.groups()[1].find('https:')>=0 or headers.groups()[1].find('HTTPS:')>=0 or hosts.groups()[0].find(':443')>=0:
				
				if hosts.groups()[0].find(':')>0:#获得no_port_host和ports
					print(hosts.groups()[0])
					re_port=re.match(rechr_port,hosts.groups()[0])
					print('re_port:',re_port.groups())
					ports=int(re_port.groups()[1])
					no_port_hosts=re_port.groups()[0]
				else:
					ports=443
					no_port_hosts=hosts.groups()[0]
				print('no_port_hosts:',no_port_hosts)
				addr_remote=socket.gethostbyname(no_port_hosts)
				
				addr_re=(addr_remote,ports)
				print(addr_re)
				try:
					remote.connect(addr_re)
				except socket.error as e:
					print('https:remote.connect error!\n:%s'%e)
					sock.close
					remote.close()
					return 0
				finally:
					print('addr_re:',addr_re)
				re_star='HTTP/1.0 200 Connection established\r\n\r\n'
				re_star=re_star.encode()
				send_data(sock,re_star)
				print(re_star)
				data=data.encode()
				print('https to remote data:%s\n----------------------\n'%data.decode('utf-8'),len(data.decode('utf-8')))
				#print('this is send connect:',send_data(remote,data))
				print('no_port_host and ports',no_port_hosts)
				#handle_tcp(sock,remote)
				handle_tcp(sock,remote)
			
		except socket.error as e:
			print(' error1!\nE:%s'%e)
		finally:
			sock.close()
			remote.close()

class server_listen(object):

	def __init__(self):
		try:
			self.server_l=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			self.server_l.bind(('0.0.0.0',9922))
			self.server_l.listen(1024)
			self.server_l.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		except:
			print('server_listen by init error!\n')
			sys.exit(0)
	def handle_socks5(self):
		try:
			self.sock.recv(256)
			reply=b"\x05\x00\x00\x01"
			reply+=socket.inet_aton('0.0.0.0')+struct.pack(">H",9922)
			self.sock.send(reply)
			
		except:
			print('error2')
	def listen_accept(self):
		try:
			#while True:
			#	sock,addr=self.server_l.accept()
			#	handle_socks5()
			#	break
			while True:
				sock,addr=self.server_l.accept()
				print(addr)
				t=threading.Thread(target=handle,args=(sock,addr))
				t.start()
				
		except socket.error as e:
			print('error3E:'%e)
def main():
	serv=server_listen()
	serv.listen_accept()

main()