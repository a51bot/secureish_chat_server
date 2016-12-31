# chat_client.py

import sys
import socket
import select

from aes_python import *
 
def chat_client():
    if(len(sys.argv) < 3) :
        print 'Usage : python chat_client.py hostname port'
        sys.exit()

    dont_break=1
    pass_hash = ""
    while dont_break != 0:
        if len(pass_hash) > 0:
            dont_break = 0
        else:
            pass_hash = create_password_hash(raw_input("Enter the password that you both know: "), 'junkgoeshere')
    
    aes = AESCipher(pass_hash) #generate the cipher

    host = sys.argv[1]
    port = int(sys.argv[2])
     
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
     
    # connect to remote host
    try :
        s.connect((host, port))
    except :
        print 'Unable to connect'
        sys.exit()
     
    print 'Connected to remote host. You can start sending messages'
    sys.stdout.write('[Me] '); sys.stdout.flush()
     
    while 1:
        socket_list = [sys.stdin, s]
         
        # Get the list sockets which are readable
        ready_to_read,ready_to_write,in_error = select.select(socket_list , [], [])
         
        for sock in ready_to_read:             
            if sock == s:
                # incoming message from remote server, s
                data = sock.recv(4096)
                if not data :
                    print '\nDisconnected from chat server'
                    sys.exit()
                else :
                    #print "data"+data
                    #check if they are messages from the server or enc
                    if "Client" in data:
                        sys.stdout.write(data) #just print it
                    else:             
                        splitup = data.split(']') #split the incoming string from the server   
                        dec = aes.decrypt(splitup[1]) #decrypt
                        if ' ' in dec: #if there is a space in the decrypted message
                            sys.stdout.write(splitup[0]+'] '+dec) #print
                            sys.stdout.write('[Me] '); sys.stdout.flush()     
                            
            
            else :
                # user entered a message
                msg = sys.stdin.readline()
                encrypted = aes.encrypt(msg+' ') #append a space so that you can tell if it was decrypted or not
                s.send(encrypted)
                #sys.stdout.write("Sent: "+encrypted)
                sys.stdout.write('[Me] '); sys.stdout.flush() 

if __name__ == "__main__":

    sys.exit(chat_client())