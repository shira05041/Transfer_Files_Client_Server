from collections import namedtuple
import os
import random
import selectors
import socket
import sqlite3
import string
import struct
import binascii
import time
import uuid
from Crypto.Cipher import AES
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from secrets import token_bytes
import zlib  # to calc crc
from main import*
from parameters import*


class Server:
    def __init__ (self, ip):
        self.ip = ip
        try:
            self.port = self.get_port()
        except Exception as err:  # if invalid port
            print(err)
            exit(1)
        self.version = SERVER_VERSION    # version of server
        self.status = 0     # status code after processing request 
        self.cur_cid = b''  # current client id
        self.AES_key = token_bytes(16)
        #open SQL database and create tables if they are not exist
        self.conn, self.cursor = self.open_sql_db()
        
         # create directory to save recieved files
        self.create_dir()
        #selector to handle requests from multiple users at the same time
        self.sel = selectors.DefaultSelector()
        
        #open server socket (TCP/IP non-blocking)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.ip, self.port))
        self.sock.listen(MAX_ACCEPTED_CONNECTIONS)
        self.sock.setblocking(False)
        #register read events on server socket
        self.sel.register(self.sock, selectors.EVENT_READ, self.accepet)

    def run(self):
        while True:
            events = self.sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)


    def accepet(self, sock, mask):
        """
        this function accepts the incoming client connections
        param sock: this server's socket
        param mask: events mask
        """
        conn, addr = sock.accept()  
        print(f'Accepted client from address: {addr}')
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.read)
        print('connection with client sucsseded') #for debug info 
        
     
     
    def read(self, conn, mask):
        """
        this function reads the recieved message
        by reading the header .
        """ 
        try:
            header = self.recieve_header(conn, mask)
            Header = namedtuple('Header', ['ClientID', 'Version', 'req_code', 'PayloadSize'])
            uh = Header._make(self.parse_header(header)) #unpaked header
           # print(uh)  # for debug info
            self.process_request(conn, mask, uh)

        except Exception as err:
            print(err)
            self.shutdown_client(conn, None)


    def process_request(self, conn, mask, uh):
        """
        Act accordingly to the received request operation from client
        uh = unpacked header after named tuple
        """

        if uh.req_code == REGISTER_REQUEST_CODE:
            self.registration_request(conn, mask, uh)
            self.response_registration(conn, mask)
            
        elif uh.req_code == CLIENT_SEND_PUBLIC_KEY:
            public_key = self.recieve_public_key(conn, mask, uh )
            self.response_public_key(conn, mask, uh, public_key)

        elif uh.req_code == CLIENT_SEND_ENCRYPTED_FILE:
            upf ,CRC = self.recieve_file(conn, mask, uh)
            self.response_recieved_file(conn, mask, upf, CRC)

        elif uh.req_code == CRC_SUCCESS:
            self.verifie_file(conn, mask, uh)
            self.response_succsess(conn, mask, uh)

        elif uh.req_code == CRC_FAILED:
            # now client will send right away again request with code 1103
            #self.read_bytes(conn, mask, uh)
            print("CRC failed waiting for client to send the file again")
            
        elif  uh.req_code == CRC_FAILED_END_PROGRAM:
            res_head = struct.pack('<BHI', self.version, END_PROCESS, EMPTY_PAYLOAD)
            self.send(conn, mask, res_head, RESPONSE_HEADER_SIZE)
            self.delete_file(conn, mask, uh)  


    def registration_request(self, conn, mask, uh): 
        """
        handles registration request. unpacks the payload from
        the client. payload consists of username and public key.
        if no errors appeared, add the new client to the clients data base table and
        return the generated uuid for the client. also update the status
        code accordingly.
        """
        payload = self.recieve_payload(conn, mask, uh.PayloadSize)
        Payload = namedtuple('Payload', ['username'])
        up = Payload._make(self.parse_payload(payload, username_size = MAX_USERNAME))
                                              
        print('Searching DB for client existence')
        self.cursor.execute("SELECT ID FROM clients WHERE ID=:uuid", {"uuid": uh.ClientID})
        if not self.cursor.fetchall():  # if the user is not registered 
            uid = uuid.uuid4().bytes_le
            username = up.username
            print(f'Registering new client with uuid: {uid}')
      
            self.cursor.execute("INSERT INTO clients (ID, Name, PublicKey, LastSeen, AES) VALUES (?, ?, ?, ?, ?)",(uid, username, NULL, time.ctime(), NULL))           
            self.conn.commit() # update the changes in DB
            
            self.status = REGISTRATION_SUCCESS
            self.cur_cid = uid
            print('data insertsd into clients DB') #for debug
        else:
            print(f'Client already exists: {self.cursor.fetchall()}, aborting registration') # returns an error message to the client
            self.status = REGISTRATION_FAILED
            self.cur_cid = uh.ClientID 


            
    def response_registration(self, conn, mask):
        """
        response from the server for recently registered/un-registered client
        """
        res_header = struct.pack('<BHI', self.version, REGISTRATION_SUCCESS, UUID_SIZE)
        res_payload = struct.pack(f'<{UUID_SIZE}s', self.cur_cid)
        self.send(conn, mask, res_header, RESPONSE_HEADER_SIZE)
        self.send(conn, mask, res_payload, UUID_SIZE)


    def recieve_public_key(self, conn, mask, uh):
        """
        server response with public key of a given client
        
        handles registration request. unpacks the public key from
        the client. payload consists of username and public key.
        if no errors appeared, add the public key to the clients data base table and
        return the AES key for the client. also update the status
        code accordingly. 
        """

        public_key = self.recieve_payload(conn, mask, uh.PayloadSize)
        Public_key = namedtuple('Payload', ['username', 'public_key'])
        upk = Public_key._make(self.parse_payload(public_key, username_size = MAX_USERNAME, public_key_size = PUB_KEY_SIZE))
        
        print(f'\nPUBLIC KEY =  {upk.public_key}\n')

        self.cursor.execute("SELECT * FROM clients WHERE ID=:uuid", {"uuid": uh.ClientID})
        if not self.cursor.fetchall():  # if ID is not in the table
            raise Exception('Cannot recieve public key, user not registered')
        else:
            self.cursor.execute("UPDATE clients SET PublicKey=:pk WHERE ID=:uuid",{"pk": upk.public_key, "uuid": uh.ClientID})# save clients public key in clients table
            self.conn.commit()
            self.status = PUBLIC_KEY_RESPONED_AES
            return upk.public_key

         



    def response_public_key(self, conn, mask, uh, public_key):
        """
        this function creates and sends server response to the client that sent public key request
        server response contains generates AES key encoded by clients public ke
        """
    
        encrypted_AES_key = self.encrypt_AES(public_key)
        self.cursor.execute("UPDATE clients SET AES=:AES_k WHERE ID=:uuid",{"AES_k": self.AES_key, "uuid": uh.ClientID})# save AES key in DB
        self.conn.commit()
        print('\nENCRYPTED AES =')
        print(binascii.hexlify(encrypted_AES_key , ' '))   
        res_header = struct.pack('<BHI', self.version, PUBLIC_KEY_RESPONED_AES, UUID_SIZE + len(encrypted_AES_key))
        res_payload = struct.pack(f'<{UUID_SIZE}s{len(encrypted_AES_key)}s', self.cur_cid, encrypted_AES_key)
        
        # send server response (containing encrypted AES key) to the client that sent public key)
        self.send(conn, mask, res_header, RESPONSE_HEADER_SIZE)
        self.send(conn, mask, res_payload, UUID_SIZE + len(encrypted_AES_key))

     
    def encrypt_AES(self, public_key):
        """
        this function encrypt the AES key with users public key using RSA encoding
        """
        print(f'AES_key =   {self.AES_key}')
        print(type(self.AES_key))
        key = RSA.importKey(public_key)
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(self.AES_key)
        return ciphertext
        
        
    
    def recieve_file(self, conn, mask, uh):
        """
        This function handles file sent request - unpacks the payload 
        the funct calls other functions to decrypt the file, save the decrypted file, and calc crc.
        returns unpaked payload and crc
        """
        recieved_file = self.recieve_payload(conn, mask, uh.PayloadSize)
        
        Recieved_file = namedtuple('Recived_file', ['ClientID', 'ContentSize', 'FileName', 'MessageConntent'])
        
        file_size = uh.PayloadSize - UUID_SIZE - CONTENT_SIZE - MAX_FILENAME
        upf = Recieved_file._make(self.parse_payload(recieved_file, ID_size = UUID_SIZE, c_size = CONTENT_SIZE, f_name = MAX_FILENAME, f_size = file_size))
        
        print(f"file size: {file_size}")

    
        print(f" in recive file ENCRYPTED CONTENT: {upf.MessageConntent}")
        dec_file = self.decrypt_file(upf.MessageConntent)
        print(f"in recive file AES key size : {len(self.AES_key)}")
        print(f"in recive file DECRYPTED CONTENT: {dec_file}")

        self.save_file(dec_file, upf)
        CRC = self.calc_CRC(dec_file)
        print("server calculated the CRC =  " + CRC) 
        return upf, CRC



    def response_recieved_file(self, conn, mask, upf, CRC):
        print('In response_recieved_file ')
        CRC = CRC.encode()
        res_header = struct.pack('<BHI', self.version, CRC_RESPONED, CRC_RESPONSE_PAYLOAD)
        #res_payload = struct.pack(f'<16s4s255s4s', self.cur_cid, upf.ContentSize, upf.FileName, CRC)
        res_payload = struct.pack(f'<{UUID_SIZE}s{CONTENT_SIZE}s{MAX_FILENAME}s{CKSUM_SIZE}s', self.cur_cid, upf.ContentSize, upf.FileName, CRC)#.encode())#to_bytes(CKSUM_SIZE, 'little'))
        
        self.send(conn, mask, res_header, RESPONSE_HEADER_SIZE)
        self.send(conn, mask, res_payload, CRC_RESPONSE_PAYLOAD)




    def decrypt_file(self, MessageConntent): 
        """
        this function returns decrypt file in bytes
        """
        cipher = AES.new(self.AES_key, AES.MODE_CBC, IV)  
        dec_file = cipher.decrypt(MessageConntent) 
        print(type(dec_file))
        return dec_file  
    



    def save_file(self, dec_file, upf):
        """
        this function save the file in recived files folder
        """
        # to give disticnt name
        index = upf.FileName.find(b'\x00') #to save the file name and not all the 255 bytes that recieved
        file_name = upf.FileName[:index].decode() 
        
        print(f'File Name: {file_name}')
        file_path = os.path.abspath(f'./recieved_files/{file_name}')
        print(f'File Path: {file_path}')

        with open(file_path, 'w') as f:
            f.write(str(dec_file))
        self.cursor.execute("INSERT INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)",
                         (upf.ClientID, file_name, file_path, False))
        self.conn.commit()                


    def  calc_CRC(self, dec_file):
        """
        this function calculate the crc of the file
        """
        crc = zlib.crc32(dec_file)
        print(f'Server crc: {crc}')
        return str(crc)


    def verifie_file(self, conn, mask, uh):
        """
        this function update the files DB after the file succesfuly accepted
        """
        print(uh)
        recieved_file = self.recieve_payload(conn, mask, uh.PayloadSize)
        Recieved_file = namedtuple('Recieved_file', ['ClientID','FileName'])
        up = Recieved_file._make(self.parse_payload(recieved_file, ID_size = UUID_SIZE, f_name = MAX_FILENAME))
        index = up.FileName.find(b'\x00')
        file_name = up.FileName[:index].decode()

        self.cursor.execute("UPDATE files SET Verified=:ver WHERE FileName=:f_name",{ "ver": True, "f_name": file_name})
        self.conn.commit()
        

    def response_succsess(self, conn, mask, uh) : 
    
        res_head = struct.pack('<BHI', self.version, END_PROCESS, EMPTY_PAYLOAD)
        self.send(conn, mask, res_head, RESPONSE_HEADER_SIZE)
        self.shutdown_client(conn, uh)


    def read_bytes(self, conn, mask, uh):
        """
        This function reads the received bytes in order to clear socket
        """
        payload = self.recieve_payload(conn, mask, uh.PayloadSize)


    def delete_file(self, conn, mask, uh):
        """
        This function deletes file from server directory after file was not verified three times
        """
        payload = self.recieve_payload(conn, mask, uh.PayloadSize)
        Payload = namedtuple('recieved_file', ['ClientID', 'FileName'])
        up = Payload._make(self.parse_payload(payload, id_size=UUID_SIZE, f_name=MAX_FILENAME))
        index = up.FileName.find(b'\x00')
        file_name = up.FileName[:index].decode()
        path_name = os.path.abspath(f'./recieved_files/{file_name}')
        if os.path.exists(path_name):
            os.remove(path_name)
        else:
            raise Exception(f"The file {file_name} does not exist")
        self.shutdown_client(conn, uh)  # close client connection socket    
    


       
    def recieve_header(self, conn, mask)-> bytes:
        """
        this function receives the header of the message.
        returns header in bytes.
        """  
        header = conn.recv(REQUEST_HEADER_SIZE) #recieve header data from socket
        if not header:
            raise Exception('Could not process request, missing header')
        if len(header) != REQUEST_HEADER_SIZE:
            raise Exception(f'Invalid header size. size shuold be {REQUEST_HEADER_SIZE}')
        return header    
            

    def parse_header(self, header) -> tuple:
        """
        This function unpacks the header occurding to given sizes (in bytes): client_id-16 bytes, version-1 byte, code-2 bytes, payload_size-4 bytes.
        header: the request header recieved from client
        returns unpacked header tuple
        """
        return struct.unpack('<16sBHI', header)  # Interpret bytes as packed binary data


    def recieve_payload(self, conn, mask, size) -> bytes:
        """
        this function receives the client payload from socket.
        conn: connection socket with client
        mask: events mask
        size: payload size (bytes)
        returns payload (bytes object)
        """
        data = conn.recv(size)  # receive payload data from socket
        if not data:
            raise Exception('Missing payload, request aborted')
        if len(data) != size:
            raise Exception(f"Payload too short, Number of received bytes ({len(data)}) != payload size specified ({size})")
        return data

    def parse_payload(self, payload, **kwargs) -> tuple:
        """
        this function gets the payload bytes object, and unpacks it in a way
        that the resulted bytes would split into categories
        according to key word arguments provided.
        payload: payload recieved from client
        kwargs: type dict, key value elements (categories in payload) 
        returns a tuple that contains the payload, split according the kwargs argument.
        """
        if len(payload) > sum(kwargs.values()):  # key word args refers as a dictionary, sum calcs the total amount of bytes in payload
            raise Exception("Could not parse payload, invalid size")
        splitter = ''
        for num_bytes in kwargs.values():
            splitter += f'{num_bytes}s'  # create format for unpacking payload
        return struct.unpack(splitter, payload)  # unpack payload to wanted fields


    def send(self, conn, mask, data, amount) -> int:
        """
        this function send respons to client through socket.
        """
        bytes_sent = conn.send(data) # send datd through socket
        if bytes_sent != amount:
            raise Exception(f'Invalied amount of bytes. sent: {bytes_sent} bytes. shuold be send: {amount} bytes.')


    def get_port(self):
        if not os.path.isfile("port.info.txt"):
            print('Can not find port.info file. useing DEFAULT_PORT')
            port = DEFAULT_PORT
        else:
            f = open("port.info.txt", "r")
            port = f.readline() # read port number
            if not(port.isdecimal()) or not (0 < len(port) < 5):
                raise Exception('Invalide port')         
            
        print('IN GET_PORT FUNC')    
        print(f'port i got: {port}')   
        return int(port)


    def open_sql_db(self):
        """
        This function opens an sqlite database. then creates a clients table and files table with the following entries: 
        clients table: ID-16 bytes, Name-255 bytes, Public Key-160 bytes, Last Seen-Date and Hour, AES-32 bytes
        files table: ID-4 bytes, FileName-255 bytes, PathName-255 bytes, verified-1 byte (boolean)
        """

        if not os.path.exists(SERVER_DB):
            open(SERVER_DB, 'ab')

        conn = sqlite3.connect(SERVER_DB)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS clients (ID BLOB, Name BLOB, PublicKey BLOB, LastSeen TEXT, AES BLOB)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS files(ID BLOB, FileName TEXT, PathName TEXT, Verified BLOB)''')
        conn.commit()
        print('Created Clients and Files Tables') #for debug info
        return conn, cursor


    def create_dir(self):
        """
        this function create a folder to seve the recieved files
        """
        print('in create_dir function')
        current_directory = os.getcwd()
        # r represents raw string..  and will cause backslashes in the string to be interpreted as actual backslashes rather than special characters
        final_directory = os.path.join(current_directory, r'recieved_files')
        #PATH_NAME = final_directory
        if not os.path.exists(final_directory):
            os.makedirs(final_directory)
        print(f'recieved files folder will be here: {final_directory}')  #for debug info

        
            
    def shutdown_client(self, conn, uh):
        """
        close socket connection to client, and unregister the connection
        from any future events. amd closes the selector, the socket, and the sql db
        param conn: client's socket connection to be closed
        """
        try:
            self.cursor.execute("SELECT Name FROM clients WHERE ID=:uuid", {"uuid": uh.ClientID})
            username = self.cursor.fetchone()
            print(f'User Name: {username}')
            
            
        except Exception as err:
            username = "Unregistered client"
        print(f'----Closing connection with client: {username}----\n\n')
        self.sel.unregister(conn) # removing client socket from selsctor
        conn.close()

    def close(self):
        """
        this function closes the selector, the socket, and the sql db
        """
        self.sel.close()
        self.sock.close()
        self.conn.close()
        



    
    
