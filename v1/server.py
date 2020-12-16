#!/usr/bin/env python3
"""Server for multithreaded application"""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import json 
import sys
import time
import random

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
            time.sleep(10)
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
    send_numP()
    time.sleep(.05)
    broadcastPlayers()
    time.sleep(.05)
    send_stock()
    msg["content"] = "Stock Shuffled!"
    broadcast(bytes(json.dumps(msg),"utf8"))
    time.sleep(.05)
    distribute()
    print("Pieces on the table: ",stock)
    msg["content"] = "Stock Distributed!"
    broadcast(bytes(json.dumps(msg),"utf8"))
    time.sleep(.05)
    msg["type"] = "doneStock"
    msg["content"] = ""
    broadcast(bytes(json.dumps(msg),"utf8"))
    time.sleep(.05)
    play()
    print("Remaining pieces: ",stock)


def send_numP():
    

    for sock in clients:
        msg = {
            "type":"numPieces",
            "content": num_pieces[str(len(addresses))]
        }
        sock.send(bytes(json.dumps(msg), "utf8"))

def send_stock():
    """Sends the stock to the clients to be shuffled"""

    global stock
    for sock in clients:
        msg = {
            "type":"rcvStock",
            "content":stock
        }
        sock.send(bytes(json.dumps(msg), "utf8"))
        
        tmp = eval(receive(sock))
        stock = tmp
        


def distribute():
    """Distriutes the stock to the clients to pick a piece and shuffled"""
    global fClient
    global stock
    client = clientRandom() 
    fClient = client
    msg = { 
            "type":"dstrStock",
            "content": stock
        }
    
    client.send(bytes(json.dumps(msg), "utf8"))
    msg = json.loads(receive(client))
    time.sleep(.05)
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

        ndone = temp_msg['ndone'] 
        msg = temp_msg
        time.sleep(.05)
    
    stock = msg["stock"]
    


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
    
    while s_nempty and (prev_state != game_state or draw) and no_winner:
        
        
        time.sleep(.05)
        if not draw:
            if c == len(clients)-1:
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
        client.send(bytes(json.dumps(msg), "utf8"))
        received = json.loads(receive(client))
            
        draw = False
        if "draw" in list(received.keys()):
            
            
            draw_msg = {
                "type": "draw",
                "content": stock
            }
            time.sleep(.05)
            client.send(bytes(json.dumps(draw_msg), "utf8"))
            if len(stock)!=0:
                draw = received["draw"]
                received_draw = json.loads(receive(client))
                stock = received_draw['stock']##implement draw type message
        
        if "win" in list(received.keys()):
            no_winner = False
            winner = client
        
        if not draw:
            game_state = received

    msg = {
        "type": "print",
        "content": "Game ended"
    }
    broadcast(bytes(json.dumps(msg),"UTF-8"))
    if not no_winner:
        msg = {
            "type": "print",
            "content": "The winner is "+str(clients[winner])
        }
        print("The winner is "+str(clients[winner]))
        broadcast(bytes(json.dumps(msg),"UTF-8"))
    

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

HOST = '127.0.0.1'
PORT = 1240
BUFSIZ = 2048
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

    