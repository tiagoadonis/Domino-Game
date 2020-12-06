#!/usr/bin/env python3
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import sys
import json
import random

# variables
numPieces = 0
stock = []
nRound = 0
points = 0
my_name= ""


def main():
    """Main function"""
    while True:
        try:
            msg = receive()
            print(msg)

            if msg == "{quit}":
                client_socket.close()
                break
            if msg == "{clients}":
                save_clients()
            if msg == "{numPieces}":
                num_pieces()
            elif msg == "{rcvStock}":
                rcv_stock()
            elif msg == "{dstrStock}":
                dstr_stock()
            elif msg == "{doneStock}":
                print(stock)
            
            '''
			if msg == "{play}":
                play_piece()
			if msg == "{wonRound}":
                print("Won round\n")
            if msg == "{lostRound}":
                lost_round()
			'''
        except OSError:  # Possibly client has left the chat.
            break

def send_name():
    print("Greetings from the server! Now type your name and press enter!")
    name = input()
    
    if name == "{quit}":
        client_socket.close()
        sys.exit("Connection closed!")
    my_name = name
    send(name)
    

def num_pieces():
    global numPieces
    numPieces = json.loads(receive())
    print(numPieces)

def dstr_stock():
    """Client Take / Not Take a piece from stock"""
    stockS = json.loads(receive())	# Stock from server
    arr = [1, 0, 0, 0, 0] # 20% probability of taking a piece
    prob = random.choice(arr)
    global stock
    global numPieces

    if prob == 1 and len(stock) != numPieces:
        stock.append(stockS[0])
        stockS = stockS[1:]
        print("Took a piece")
    else:
        p = random.randint(0, 1) # 50% probability of swaping a piece
        if p == 1 and len(stock) == numPieces:
            chg = random.choice(stock)
            b = []
            for a in stock:
                if a != chg:
                    b.append(a)
                else:
                    b.append(stockS[0])
                    stockS = stockS[1:]
                    stockS.append(a)
            stock = b
            print("Swap a piece")
    random.shuffle(stockS)
    send(json.dumps(stockS))


def rcv_stock():
    """Client Shuffle and sends stock to Server"""
    stk = json.loads(receive())
    random.shuffle(stk)
    print(stk)
    send(json.dumps(stk))
    print("Sent!")

def receive():
    """Handles receiving of messages"""
    return client_socket.recv(BUFSIZ).decode("utf8")


def send(my_msg):  # event is passed by binders.
    """Handles sending of messages"""
    msg = my_msg
    my_msg = ""  # Clears input field.
    client_socket.send(bytes(msg, "utf8"))
    if msg == "{quit}":
        client_socket.close()

'''
def play_card():
    """play a card"""
    global nRound
    table = json.loads(receive())               #receive table
    nRound += 1                                 #increment round 

    if (len(table) == 0 and nRound == 1):       #firts play of the game 
        subDeck = []
        for i in deck:                          #reorganize by naipe
            if i[1] != 'H':
                subDeck.append(i)               #subDeck without Hearts
        card = random.choice(subDeck)           #play random card
    
    elif len(table) == 0:                    
        card = random.choice(deck)
    
    else:
        naipe = table[0][1]                     #naipe to respect
        subDeck = []
        for i in deck:                          #reorganize by the naipe to respect
            if i[1] == naipe:
                subDeck.append(i)
        if len(subDeck) == 0:
            card = random.choice(deck)
        else:
            card = random.choice(subDeck)
    
    deck.remove(card)                           #remove selected card from deck     
    send(json.dumps(card))                      #send card
  

def lost_round():
    global points
    points = json.loads(receive())
    print("Lost round\nPoints: %d\n" % points)
'''

#----Sockets part----#
HOST = "127.0.0.1"
PORT = 1240
BUFSIZ = 1024
ADDR = (HOST, PORT)

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

main_thread = Thread(target=main)
main_thread.start()

my_msg = ""
while 1:
    my_msg = ""  # For the messages to be sent.
    my_msg = input()
    if my_msg == "{quit}":
        client_socket.close()
        sys.exit("Connection closed!")
    if my_name == "":
        my_name = my_msg

    send(my_msg)
    