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
players= []

def main():
    """Main function"""
    while True:
        try:
            msg = json.loads(receive())
            if msg["type"] == "print":
                print(msg["content"])

            if msg["type"] == "quit":
                client_socket.close()
                break
            if msg["type"] == "players_info":
                save_players(msg["content"])
            if msg["type"] == "numPieces":
                num_pieces(msg["content"])
            elif msg["type"] == "rcvStock":
                rcv_stock(msg["content"])
            elif msg["type"] == "dstrStock":
                dstr_stock(msg["content"])
            elif msg["type"] == "doneStock":
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
    
def save_players(content):
    for name in content:
        if name != my_name:
            players.append(name)

def num_pieces(content):
    global numPieces
    numPieces = content
    print("Number of pieces per player: "+str(numPieces))

def dstr_stock(content):
    """Client Take / Not Take a piece from stock"""

    stockS = content	# Stock from server
    arr = [1, 0, 0, 0, 0] # 20% probability of taking a piece
    prob = random.choice(arr)
    global stock
    global numPieces
   
    #while len(stockS) == 1:
        #stockS=stockS[0]
    #print(stockS)
    if len(stockS) != (28 - ((len(players)+1)*numPieces)):
        if prob == 1 and len(stock) != numPieces:
            
            stock.append(stockS[0])
            temp = stockS[1:]
            stockS = temp
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
            #else:
                
                #print("Random shuffle",random.shuffle(stockS))

        #print(stock)
        #print(stockS)
        #print("AAAAAAAAAAAAAAAAAAAAAAA")
        sendRandomPlayer(stockS)

    else:
        dic = {
            "sendTo" : "done",
            "ndone": False,
            "stock"  : stockS
        }
        send(str(json.dumps(dic)))

def rcv_stock(content):
    """Client Shuffle and sends stock to Server"""
    stk = content
    random.shuffle(stk)
    while len(stk) == 1:
            stk=stk[0]
    send(str(stk))
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

def sendRandomPlayer(stock_temp):  # event is passed by binders.
    """Handles sending of messages"""

    dic = {
        "ndone": True,
        "sendTo" : random.choice(players),
        "stock"  : stock_temp
    }
    client_socket.send(bytes(json.dumps(dic), "utf8"))
    

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
my_name = sys.argv[1]
send(my_name)
print(receive())
#if receive() == "fail":
    #print("AAAAAAAAA")
    #client_socket.close()
main_thread = Thread(target=main)
main_thread.start()

my_msg = ""
while 1:
    my_msg = ""  # For the messages to be sent.
    my_msg = input()
    '''
    if my_name == "" and my_msg != "{quit}":
        my_name = my_msg
    '''
    send(my_msg)
    if my_msg == "{quit}":
        client_socket.close()
        sys.exit("Connection closed!")
    

    
    