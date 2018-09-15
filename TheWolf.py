#!/usr/bin/python
# -*- coding: latin-1 -*-


#Copright(c) ByteZero
#
#Este programa é um portscan simples criado por ByteZero
#Não me responsabilizo por nenhuma ação ilícita realizada
#com esta ferramenta.
#
#Não é proibido a modificação do código, porém, se for
#modifica-lo é proibido a remoção deste cabeçalho.
#
#Bay

import socket
import sys
import getopt
import os
import time

try:
	import socket
except:
	print "OPS! Erro ao importar o packate-tool-scapy"

banner = '''
\n\033[92m*******************************************************************
*	 _____ _        __        __    _  __ 			  *
*	|_   _| |__   __\ \      / /__ | |/ _|			  *
*	  | | | '_ \ / _ \ \ /\ / / _ \| | |_ 			  *
*	  | | | | | |  __/\ V  V / (_) | |  _|			  *
*	  |_| |_| |_|\___| \_/\_/ \___/|_|_|                      *
*                                                                 *
*  TheWolf V. 1.0						  *
*  Coded by ByteZero						  *
*  Contact telegram: @ByteZero					  *
*  Canal telegram: @securecodebrazil				  *
*								  *
* "Eu dei a vocês autoridade para pisarem sobre cobras            *
*  e escorpiões e todo o poder do inimigo: nada lhe               *
*  fará dano" (Lc 10:19)"					  *
*******************************************************************\033[92m\n
'''
print banner

def usage():
	comm = os.path.basename(sys.argv[0])

	if os.path.dirname(sys.argv[0]) == os.getcwd():
		comm = "./" + comm
	print '''\033[92m[+]Modo de uso: TheWolf opções \033[92m\n'''
	print "		-v = Varrer alvo por Ip "
	print "		-l = limite de portas para scanear"
	print "\nExemplos:"
	print "		" + comm + " -v 192.168.100.0 -l 80"


# Função que valida o tamanho dos argumentos
def start(argv):
	if len(sys.argv) < 3:
		usage()
		sys.exit()
	try:
		opts, argv = getopt.getopt(argv, "s:v:l:")
		pass
	except getopt.GetopError:
		usage()
		sys.exit()
	#Varredura de Host	
	TopPort = False
	scanner = False
	limit = 6535
	lista = []
	salve = True
	 
	for opt, arg in opts:
		if opt == '-v':
			scanner = True
			word = arg
			continue
		elif opt == '-l':
			limit = int(arg)
			break
		
	if scanner == True:
		print "\n\033[92m[+] - Resultado da varredura no HOST/IP: %s\033[92m"%(word)
		print "******************************************************************"
		time.sleep(0.3)
		print "[*] Date/Hour: ", time.asctime()
		print "[*] limit Ports: %s"%limit

		for porta in range(0,limit):
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(0.1)
			if s.connect_ex((word, porta)) == 0:
				lista.append(porta)
		if len(lista) == 0:
			print "******************************************************************"
			print "\n[-] Sorry: Nenhuma porta TCP entre 0 - %s aberta foi encontrada\n"%limit
			sys.exit()
		if len(lista) != []:
			var = len(lista)
			print "[*] Total de portas abertas [%s]"%var
			print "******************************************************************"
			print "\n[+] Porta(s): %s\n"%(lista)
				
if __name__ == "__main__":
	try:
		start(sys.argv[1:])
	except KeyboardInterrupt:
		print "Varredura interrompida pelo o usuário"
	except:
		sys.exit()
