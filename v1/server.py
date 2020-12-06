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

#Client info
clients=[]

def accept_incoming_connections():
    """Sets up handling for incoming clients"""

    while True:
        if len(addresses) == 5 :
            client, client_address = SERVER.accept()
            client.send(bytes("{quit}", "utf8"))
            client.close()
        else:
            client, client_address = SERVER.accept()
            print("%s:%s has connected." % client_address)
            client.send(bytes("Greetings from the server! Now type your name and press enter!", "utf8"))
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
    welcome = 'Welcome %s! If you ever want to quit, type {quit} to exit.' % name
    client.send(bytes(welcome, "utf8"))
    msg = "%s has joined the game!\n" % name
    broadcast(bytes(msg, "utf8"))
    clients[client] = name
    # If 2 <= players <= 4, then start game in 10 sec if no one shows up!
    broadcastPlayers()
    if len(addresses) >= 2 and len(addresses) <= 5:
        len1 = len(addresses)
        msg = "If no one else appears in the next 20 seconds, the game will begin!"
        broadcast(bytes(msg, "utf8"))
        time.sleep(20)
        if len(addresses) == len1:
            check_start = True
    
    


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
    msg = "The Game is going to Start!"
    broadcast(bytes(msg,"utf8"))
    time.sleep(.05)
    send_numP()
    time.sleep(.05)
    send_stock()
    msg = "Stock Shuffled!"
    broadcast(bytes(msg,"utf8"))
    time.sleep(.05)
    distribute()
    msg = "Stock Distributed!"
    broadcast(bytes(msg,"utf8"))
    time.sleep(.05)
    msg = "{doneStock}"
    broadcast(bytes(msg,"utf8"))
    time.sleep(.05)
    #play()


def send_numP():
    msg = "{numPieces}"
    broadcast(bytes(msg,"utf8"))

    for sock in clients:
        sock.send(bytes(json.dumps(num_pieces[str(len(addresses))]), "utf8"))

def send_stock():
    """Sends the stock to the clients to be shuffled"""

    msg = "{rcvStock}"
    broadcast(bytes(msg,"utf8"))

    global stock
    for sock in clients:
        sock.send(bytes(json.dumps(stock), "utf8"))
        tmp = json.loads(receive(sock))
        stock.clear()
        stock = stock + tmp
        


def distribute():
    """Distriutes the stock to the clients to pick a piece and shuffled"""
    global fClient
    global stock
    stockClients = stock
    client = clientRandom() 
    fClient = client
    msg = "{dstrStock}"
    client.send(bytes(msg,"utf8"))
    time.sleep(.05)
    client.send(bytes(json.dumps(stockClients), "utf8"))
    stockClients = json.loads(receive(client))

    while len(stockClients) != (28-(len(addresses)*num_pieces[str(len(addresses))])):
        client = clientRandom(client)
        client.send(bytes(msg,"utf8"))
        time.sleep(.05)
        client.send(bytes(json.dumps(stockClients), "utf8"))
        stockClients = json.loads(receive(client))


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
    
    broadcast(bytes(json.dumps(players_info),"UTF-8"))


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
BUFSIZ = 1024
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