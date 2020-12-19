#!/usr/bin/env python3
"""Server for multithreaded application"""
from symmetric_cipher import *
from asymmetric_cipher import *
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import json 
import sys
import time
import random
import base64

# Points 
'''
pClient1 = 0
pClient2 = 0
pClient3 = 0
pClient4 = 0
'''

# First Client
fClient = None

# Check if game is about o start 
check_start = False

# Number of pieces per client
num_pieces = {  '2': 7,
                '3': 5,
                '4': 4,
                '5': 3}

# The Stock
stock = ['0-0', '0-1', '0-2', '0-3', '0-4', '0-5', '0-6', 
        '1-1', '1-2', '1-3', '1-4', '1-5', '1-6', 
        '2-2', '2-3', '2-4', '2-5', '2-6',
        '3-3', '3-4', '3-5', '3-6',
        '4-4', '4-5', '4-6',
        '5-5', '5-6',
        '6-6'] 
game_state = {}    
sharedBase = 5
sharedPrime = 131
pseudo_stock = []
stock_4players = []
pseudo_stock_keys = {}
players_public_keys = {}


def accept_incoming_connections():
    """Sets up handling for incoming clients"""

    while True:
        if len(addresses) == 5 :
            client, client_address = SERVER.accept()
            msg= {
                "type":"quit",
                "content":""
            }
            client.send(bytes(json.dumps(msg), "utf8"))
            client.close()
        else:
            client, client_address = SERVER.accept()
            print("%s:%s has connected." % client_address)
            msg= {
                "type":"print",
                "content":"Greetings from the server! Wait for other players to join!"
            }
            client.send(bytes(json.dumps(msg), "utf8"))
            addresses[client] = client_address
            Thread(target=handle_client, args=(client,)).start()
        


def start_game():
    global check_start
    while True:
        if check_start :
            Thread(target=game).start()
            check_start = False


def handle_client(client):  # Takes client socket as argument.
    """Handles a single client connection"""

    global check_start
    name = receive(client)
    
    if (client not in clients.keys()) and name!="" and (name not in clients.values()) or name == "done":
    
        welcome = 'Welcome %s! If you ever want to quit, type {quit} to exit.' % name
        msg= {
            "type":"print",
            "content":welcome
        }
        #client.send(bytes(welcome, "utf8"))
        client.send(bytes(json.dumps(msg), "utf8"))
        msg["content"] = "%s has joined the game!\n" % name
        broadcast(bytes(json.dumps(msg), "utf8"))
        clients[client] = name
        # If 2 <= players <= 4, then start game in 10 sec if no one shows up!

        if len(addresses) >= 2 and len(addresses) <= 5:
            len1 = len(addresses)
            msg["content"] = "If no one else appears in the next 20 seconds, the game will begin!"
            broadcast(bytes(json.dumps(msg), "utf8"))
            time.sleep(3)
            if len(addresses) == len1:
                check_start = True
    else:
        msg= {
                "type":"quit",
                "content":""
            }
        client.send(bytes(json.dumps(msg), "utf8"))
        client.close()
    
def receive(client):
    """Handles receiving of messages"""

    rcv = client.recv(BUFSIZ).decode("utf8")
    if rcv == bytes("{quit}", "utf8"):
        client.close()
        msg = "The Game has ended!"
        broadcast(bytes(msg,"utf8"))
        sys.exit(0)
    else:
        return rcv


def broadcast(msg, prefix=""):  # prefix is for name identification.
    """Broadcasts a message to all the clients"""

    for sock in clients:
        sock.send(bytes(prefix, "utf8")+msg)


def game():
    """Main function of the Game"""
    msg = {
        "type":"print",
        "content":""
    }
    msg["content"] = "The Game is going to Start!"
    broadcast(bytes(json.dumps(msg),"utf8"))
    time.sleep(.05)
    setUpServerClientDH()
    time.sleep(.05)
    send_numP()
    time.sleep(.05)
    pseudonymizeStock()
    time.sleep(.05)
    send_stock()
    msg["content"] = "Stock Shuffled!"
    broadcast(bytes(json.dumps(msg),"utf8"))
    time.sleep(.05)
    broadcastPlayers()
    time.sleep(.05)
    setUpClientDH()
    time.sleep(.05)
    distribute()
    time.sleep(.05)
    #print("Pseudo stock: ", pseudo_stock)
    distributeCiphered()
    time.sleep(.05)
    #print("Ciphered stock: ", pseudo_stock)
    print("Pieces on the table: ",stock)
    msg["content"] = "Stock Distributed!"
    broadcast(bytes(json.dumps(msg),"utf8"))
    time.sleep(.05)
    distributeDecipherKeys()
    time.sleep(.05)
    askPublicKeys()
    time.sleep(.05)
    msg["type"] = "doneStock"
    msg["content"] = ""
    broadcast(bytes(json.dumps(msg),"utf8"))
    time.sleep(.05)
    play()
    print("Remaining pieces: ",stock)

def setUpServerClientDH():

    for c in list(clients.keys()):
        
        secret = random.randint(1,16)
        value = ( sharedBase**secret ) % sharedPrime

        msg = {
            "type" : "server_DH",
            "content" : value
        }
        c.send(bytes(json.dumps(msg),"utf-8"))
        client_DH[c] = (int(receive(c))** secret) % sharedPrime

def setUpClientDH():

    for client in list(clients.keys()):

        msg_tosend = {
            "type" : "setUpClientDH",
            "content": ""
        }
        client.send(bytes(json.dumps(msg_tosend),"utf-8"))
        a = receive(client)
        received = json.loads(a)
        while "done" not in list(received.keys()):
            if "sendTo" in list(received.keys()):
                rcv_name = received["sendTo"]
                for c,name in clients.items():
                    if name == rcv_name:
                        c.send(bytes(json.dumps(received["content"]),"utf-8"))
            client.send(bytes(json.dumps(msg_tosend),"utf-8"))
            received = json.loads(receive(client))
    
    for client in list(clients.keys()):
        msg_tosend2 = {
                "type" : "calculate_DH",
                "content": ""
            }
        
        client.send(bytes(json.dumps(msg_tosend2),"utf-8"))

    

def send_numP():
    

    for sock in clients:
        msg = {
            "type":"numPieces",
            "content": num_pieces[str(len(addresses))]
        }
        sock.send(bytes(json.dumps(msg), "utf8"))

def pseudonymizeStock():
    global pseudo_stock
    global pseudo_stock_keys

    l_pwd = []
    pwd = str(random.randint(1,100))
    l_pwd.append(pwd)
    pseudo_cipher = SymmetricCipher(pwd)
    temp = stock.copy()
    i = 0
    while len(temp) != 0:
        random_piece = random.choice(temp)
        temp.remove(random_piece)
        pseudo_stock.append((i,pseudo_cipher.cipher(random_piece,pseudo_cipher.key)))
        pseudo_stock_keys[i] = {
            "piece": random_piece,
            "key" : pseudo_cipher.key
        }

        while pwd in l_pwd:
            pwd = str(random.randint(1,100))
        
        l_pwd.append(pwd)
        pseudo_cipher = SymmetricCipher(pwd)

        i += 1



def send_stock():
    """Sends the stock to the clients to be shuffled"""

    global stock
    global pseudo_stock

    for sock in clients:
        msg = {
            "type":"rcvStock",
            "content":stock
        }
        sock.send(bytes(json.dumps(msg), "utf8"))
        
        tmp = eval(receive(sock))
        stock = tmp

    pseudo_stock = serializePseudo(pseudo_stock)
    for sock in clients:
        msg = {
            "type":"rcvPseudoStock",
            "content": pseudo_stock
        }
        sock.send(bytes(json.dumps(msg), "utf8"))

        rcv = receive(sock)
        rcv_msg = json.loads(rcv)
        
        pseudo_stock = rcv_msg["pseudo_randomized"]#deserializeStock(rcv_msg["pseudo_randomized"])



def distribute():
    """Distriutes the stock to the clients to pick a piece and shuffled"""
    
    global stock
    client = clientRandom() 
    msg = { 
            "type":"dstrStock",
            "content": stock
        }
    client.send(bytes(json.dumps(msg), "utf8"))
    msg = json.loads(receive(client))
    ndone = True
    while ndone:
      
        msg_tosend = { 
                "type":"dstrStock",
                "content": msg['stock']
            }
        for c,name in clients.items():
            if name == msg['sendTo']:
                c.send(bytes(json.dumps(msg_tosend), "utf8"))
                temp_msg = json.loads(receive(c))
                
        if "ndone" in list(temp_msg.keys()):
            ndone = temp_msg['ndone'] 
        msg = temp_msg

    stock = msg["stock"]


def distributeCiphered():
    """Distriutes the stock to the clients to pick a piece and shuffled"""
    
    global stock_4players
    global pseudo_stock
    client = clientRandom() 
    msg = { 
            "type":"dstrCipheredStock",
            "content": pseudo_stock
        }
    client.send(bytes(json.dumps(msg), "utf8"))
    msg = json.loads(receive(client))
    ndone = True
    while ndone:
        
        msg_tosend = { 
                    "type":"dstrCipheredStock",
                    "from": clients[client],
                    "content": msg['content']
                }
        for c,name in clients.items():
            if name == msg['sendTo']:
                c.send(bytes(json.dumps(msg_tosend), "utf8"))
                temp_msg = json.loads(receive(c))
                client = c
                
        if "ndone" in list(temp_msg.keys()):
            ndone = temp_msg['ndone'] 
        msg = temp_msg
        time.sleep(.05)
    
    stock_4players = msg["ciphered_stock"]
    pseudo_stock = msg["ciphered_stock"]

def distributeDecipherKeys():
    i = len(clients) - 1
    clients_sock = list(clients.keys())
    while i!=-1:
        c1 = clients_sock[i]
        msg = {
            "type": "returnCipherStockKeys",
            "content": "",
        }
        c1.send(bytes(json.dumps(msg), "utf8"))
        temp_msg = json.loads(receive(c1))
        
        for serialcipher in list(temp_msg.keys()):
            if serialcipher in pseudo_stock:#test which are in the table
                serialkey = temp_msg.pop(serialcipher)#if in the table remove from those to be sent to the players
                #decipher those on pseudo stock 
                ciphered = deserializeBytes(serialcipher)
                key = deserializeBytes(serialkey)
                deciphered = SymmetricCipher.s_decipher(ciphered,key)
                pseudo_stock.remove(serialcipher)
                if i == 0:
                    deciphered = eval(deciphered)
                    pseudo_stock.append(deciphered)
                else:
                    serialdeciphered = serializeBytes(deciphered)
                    pseudo_stock.append(serialdeciphered)

        for c2 in list(clients.keys()):
            decipher_msg = {
                "type": "decipherStock",
                "from": clients[c1],
                "content" : temp_msg
            }
            c2.send(bytes(json.dumps(decipher_msg), "utf8"))
            receive(c2)
        #for c2 in list(clients.keys()):
            #send the rest of the keys to all
        i-=1

def askPublicKeys():
    global players_public_keys
    client = clientRandom() 
    msg = { 
            "type":"insertPublicKeys",
            "content": {}
        }
    client.send(bytes(json.dumps(msg), "utf8"))
    msg = json.loads(receive(client))
    ndone = True
    while ndone:
        
        msg_tosend = { 
                    "type":"insertPublicKeys",
                    "from": clients[client],
                    "content": msg['content']
                }
        for c,name in clients.items():
            if name == msg['sendTo']:
                c.send(bytes(json.dumps(msg_tosend), "utf8"))
                temp_msg = json.loads(receive(c))
                client = c
                
        if "ndone" in list(temp_msg.keys()):
            ndone = temp_msg['ndone'] 
        msg = temp_msg
    
    players_public_keys = msg["public_keys"] #need deserialize
    print(players_public_keys)

def clientRandom(last=None):
    """Returns a random client, excluding last one"""
    b = []
    if last == None:
        return random.choice(list(clients))
    else:
        for a in clients:
            if a != last:
                b.append(a)
        return random.choice(b)

def broadcastPlayers():
    players_info = {}
    for c in clients:
        players_info[clients[c]] = addresses[c]
    msg = {
        "type": "players_info",
        "content": players_info
    }
    broadcast(bytes(json.dumps(msg),"UTF-8"))

def play():
    c = -1
    global game_state
    global stock
    prev_state = {"A":"a"}
    no_winner = True  
    winner = None
    draw = False
    s_nempty = len(stock) != 0
    
    while s_nempty and (prev_state != game_state or draw) and no_winner:#while stock not empty after a round and (the state of previous the previous round is different to the current
                                                                        # or a player drew) and there is no winner
        
        time.sleep(.05)
        if not draw: #if the last play was a draw dont enter
            #proceed if the last play wasnt a draw 

            if c == len(clients)-1:# if got to the last player, update client to the first player and update previous game state and check if stock is empty
                prev_state = game_state
                s_nempty = len(stock) != 0
                c = 0
            else:
                c += 1
        
        msg = {
            "type": "game_state",
            "content": game_state
        }
        
        client = list(clients.keys())[c]
        client.send(bytes(json.dumps(msg), "utf8"))#send game-state to current client
        received = json.loads(receive(client))#wait for response
            
        draw = False
        if "draw" in list(received.keys()):# if response was a draw
            
            
            draw_msg = {
                "type": "draw",
                "content": stock
            }
            time.sleep(.05)
            client.send(bytes(json.dumps(draw_msg), "utf8"))#send stock to player with type draw
            if len(stock)!=0:#if the stock wasnt empty
                draw = received["draw"] #update variable draw to True
                received_draw = json.loads(receive(client)) 
                stock = received_draw['stock']#update stock with the received after client draw
        
        if "win" in list(received.keys()): #if response had a win warning
            no_winner = False #update no winner to false
            winner = client   #save the client that won
        
        if not draw:
            game_state = received # if last response wasnt a draw update game_state

    msg = {
        "type": "print",
        "content": "Game ended"
    }
    broadcast(bytes(json.dumps(msg),"UTF-8")) # send game ended to all players
    if not no_winner: #if winner
        msg = {
            "type": "print",
            "content": "The winner is "+str(clients[winner])
        }
        print("The winner is "+str(clients[winner]))
        broadcast(bytes(json.dumps(msg),"UTF-8"))#send winner to all players
    
def serializeBytes(bit):
    return base64.encodebytes(bit).decode("ascii")
    
def deserializeBytes(string):
    return base64.decodebytes(string.encode("ascii"))

def serializeStock(rcv_stock):
    send_stock = []
    for i in range(len(rcv_stock)):
        send_stock.append(serializeBytes(rcv_stock[i]))

    return send_stock

def deserializeStock(rcv_stock):
    send_stock = []
    for i in range(len(rcv_stock)):
        send_stock.append(serializeBytes(rcv_stock[i]))
            
    return send_stock
    
def serializePseudo(rcv_pseudo):
    send_stock = []
    for i in range(len(rcv_pseudo)):
        send_stock.append((rcv_pseudo[i][0],serializeBytes(rcv_pseudo[i][1])))
   
    return send_stock

'''
def clientsListOrder(first):
    clts = []
    for a in list(clients)[list(clients).index(first):]:                                       
        clts.append(a)
    while len(clts) != 4:
        for a in clients:                                       
            if a not in clts:
                clts.append(a)
    return clts


def result(table, clientsL):
    """Gives the result of round"""
    loser = [table[0], clientsL[0]]                                 # Loser starts as the first client
    naipe = table[0][1]                                             # Naipe of first client
    for i in table[1:]:                                             # Iterates through the list
        if i[1] == naipe:                                           # If naipe of first equals naipe of i
            if letterNum(i[0]) > letterNum(loser[0][0]):            # If number of i > number of first
                loser = [i, clientsL[table.index(i)]]               # New loser of round -> loser=[card, client]   
    print(table)

    for c in clientsL:
        if loser[1] == c:
            msg = "{lostRound}"                                     # Client lost round
            c.send(bytes(msg, "utf8"))
            time.sleep(.05)
            point = points(table)
            print("Points: %d\n" % point)
            c.send(bytes(json.dumps(point), "utf8"))
        else:
            msg = "{wonRound}"                                      # Client won round
            c.send(bytes(msg, "utf8"))
            time.sleep(.05)
            

    global pClient1, pClient2, pClient3, pClient4
    for l in clients:                                               # Assign points to clients
        if loser[1] == l:
            idx = list(clients).index(l)
            if idx == 0:
                pClient1 += points(table)
            elif idx == 1:
                pClient2 += points(table)
            elif idx == 2:
                pClient3 += points(table)
            elif idx == 3:
                pClient4 += points(table)


def points(table):
    points = 0
    for i in table:
        if i == 'QS':
            points += 13
        elif i[1] == 'H':
            points += 1
    return points


def letterNum(letter):
    switch = {
        '2': 2,
        '3': 3,
        '4': 4,
        '5': 5,
        '6': 6,
        '7': 7,
        '8': 8,
        '9': 9,
        'T': 10,
        'J': 11,
        'Q': 12,
        'K': 13,
        'A': 14
    }
    return switch.get(letter)


def play():
    """Play the game"""
    table = []
    global fClient
    for i in range(13):                                     # game is composed of 13 rounds
        msg = ("Round %d" % i)
        print(msg)
        broadcast(bytes(msg,"utf8"))
        time.sleep(.05)
        clts = clientsListOrder(fClient)
        for c in clts:                                      # turn of each client
            msg = "{play}"
            c.send(bytes(msg,"utf8"))
            time.sleep(.05)
            c.send(bytes(json.dumps(table),"utf8"))
            card = json.loads(receive(c))
            table.append(card)
            print(card)
        result(table, clts)
        table = []
    
    print("Client 1 : %d" % pClient1)
    print("Client 2 : %d" % pClient2)
    print("Client 3 : %d" % pClient3)
    print("Client 4 : %d" % pClient4)
'''

clients = {}
addresses = {}
client_DH = {}

HOST = '127.0.0.1'
PORT = 1240
BUFSIZ = 32768
ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)


if __name__ == "__main__":
    SERVER.listen(5)
    print("Waiting for connection...")
    ACCEPT_THREAD_1 = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD_2 = Thread(target=start_game)
    ACCEPT_THREAD_1.start()
    ACCEPT_THREAD_2.start()
    ACCEPT_THREAD_1.join()
    ACCEPT_THREAD_2.join()
    SERVER.close()

    