#!/usr/bin/env python3
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import sys
import json
import random
import time

# variables
numPieces = 0
stock = []
nRound = 0
points = 0
my_name= ""
players= []
srv_stock_empty = False
players_DH = {}
server_DH = 0

def main():
    """Main function"""
    while True:
        try:
            a = receive()
            msg = json.loads(a)

            
            if msg["type"] == "print":
                print(msg["content"])
                if msg["content"].find("The winner is") != -1:
                    if msg["content"].find(my_name)!=-1:
                        print("I won!!!!!!!!!")
                    print("My stock: ", stock)
                    print("Shared keys: ",players_DH)
            
            elif msg["type"] == "server_DH":
                getServerKeyDH(msg["content"])
            elif msg["type"] == "setUpClientDH":
                setUpClientDH()
            elif msg["type"] == "client_DH":
                saveValueDH(msg["content"])
            elif msg["type"] == "calculate_DH":
                calculateKeyDH()
            elif msg["type"] == "quit":
                client_socket.close()
                break
            elif msg["type"] == "players_info":
                save_players(msg["content"])
            elif msg["type"] == "numPieces":
                num_pieces(msg["content"])
            elif msg["type"] == "rcvStock":
                rcv_stock(msg["content"])
            elif msg["type"] == "dstrStock":
                dstr_stock(msg["content"])
            elif msg["type"] == "doneStock":
                print("My stock: ",stock)
            elif msg["type"] == "game_state":
                play(msg["content"])
            elif msg["type"] == "draw":
                draw(msg["content"])
                
            
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
    #save other players names in order
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
   
    if len(stockS) != (28 - ((len(players)+1)*numPieces)): #while the stock received from the server isnt the right size repeat
        if prob == 1 and len(stock) != numPieces: #take a piece
            
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
            else:
                random.shuffle(stockS)#if none of the others happen shuffle

        
        sendRandomPlayer(stockS)#Send to server to be routed to a random player

    else:
        dic = {
            "sendTo" : "done",
            "ndone": False,
            "stock"  : stockS
        }
        send(str(json.dumps(dic))) # when finished send to server with flag ndone = False

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

def sendRandomPlayer(stock_temp):  #ask the server to send the message to a random player choosen by me
    """Handles sending of messages"""

    dic = {
        "ndone": True,
        "sendTo" : random.choice(players),
        "stock"  : stock_temp
    }
    client_socket.send(bytes(json.dumps(dic), "utf8"))
    
def play(game_state):

    if len(game_state) != 0: # after first play
        played = False
        for k in list(game_state.keys()):
            if not played:
                piece = game_state[k]

                for n in list(piece.keys()):
                    changed = False
                    if not played:
                        if not piece[n] and len(n) > 1:#look for connections on double pieces
                            number=list(piece.keys())[-1] #get the number on the double piece  (stored on the last position of each double piece like : '"4": True')
                            d = getDoublePiece(number)#look for a double piece to connect to 'n' of 'piece'
                            if d is None:
                                p = getPiece(number)  #look for a normal piece to connect to 'n' of 'piece'
                                if p is not None:
                                    #add piece to game state
                                    played = True#update played
                                    changed = True#upate changed
                                    pos = p.find(number) #find which number will attach to the piece
                                    if pos == 0:  #if first number set to true others stay false to be attached later
                                        game_state[len(game_state)] = {
                                            str(p[0]) : True,
                                            str(p[-1]): False,
                                        }
                                    else:          #if second number set to true others stay false to be attached later
                                        game_state[len(game_state)] = {
                                            str(p[0]) : False,
                                            str(p[-1]): True,
                                        }
                            else:
                                #add double piece to game state
                                played = True #update played
                                changed = True#upate changed
                                game_state[len(game_state)] = { #always attach it on the side
                                            "d1" : True,        # d1 and d2 represent the possible connection on the middle of the piece
                                            "d2" : False,
                                            "s1" : False,       # s1 and s2 represent the possible connection on the edges(or the numbers) just like the normal pieces
                                            "s2": False,
                                            str(d[0]): True,    # put the value of both numbers as key and set it to True to avoid other pieces attaching to it
                                        }
                        elif not piece[n]:#look for connections on normal pieces similar to the if above
                            d = getDoublePiece(n) 
                            if d is None:
                                p = getPiece(n)
                                if p is not None:
                                    
                                    played = True
                                    changed = True
                                    pos = p.find(n)
                                    if pos == 0:
                                        game_state[len(game_state)] = {
                                            str(p[0]) : True,
                                            str(p[-1]): False,
                                        }
                                    else:
                                        game_state[len(game_state)] = {
                                            str(p[0]) : False,
                                            str(p[-1]): True,
                                        }
                            else:
                                
                                played = True
                                changed = True
                                game_state[len(game_state)] = {
                                            "d1" : True,
                                            "d2" : False,
                                            "s1" : False,
                                            "s2": False,
                                            str(d[0]): True,  
                                        }
                            
                    if changed:# if any piece was attached set the respective position where it attached to true
                        game_state[k][n] = True
        
        if not played and not srv_stock_empty: #if wasnt able to play and server stock isnt empty ask to draw another piece
            #try draw
            send_msg = {
                "draw" : True
            }
            send(json.dumps(send_msg))
        else: 
            if len(stock) == 0:#if my stock is empty tell the server i won and send the last game_state
                send_msg = {
                    "win" : True,
                    "game-state": game_state
                }
                send(json.dumps(send_msg))
            else: # wasnt able to play, send game state to server
                send(json.dumps(game_state))
    else: #first play, choose random piece and attach its "connections" to the game state
        piece = random.choice(stock)
        stock.remove(piece)
        if piece[0] == piece[-1]:
            game_state[0] = {
                                "d1" : True,
                                "d2" : False,
                                "s1" : False,
                                "s2": False,
                                str(piece[0]): True,  
                            }
        else:
            game_state[0] = {
                str(piece[0]): False,
                str(piece[-1]): False
            }
        send(json.dumps(game_state))

def draw(rcv_stock):
    
    if len(rcv_stock) != 0: # if the stock received form the server isnt empty, take a piece and send the rest
        stock.append(rcv_stock[0])
        temp = rcv_stock[1:]
        rcv_stock = temp
        dic = {
                "stock"  : rcv_stock
            }
        send(str(json.dumps(dic)))
    else: #if the stock was empty update global variable
        srv_stock_empty = True

def getDoublePiece(n): #get first double piece available with the number n
    for p in stock:
        if p.find(n+"-"+n) != -1:
            stock.remove(p)
            return p
    return None

def getPiece(n):#get first piece available with the number n
    for p in stock:
        if p.find(n) != -1:
            stock.remove(p)
            return p
    return None

def setUpClientDH():

    done = True
    for p in players:
        if p not in list(players_DH.keys()) and done:
            done = False
            getKeyDH(p)
        elif done:
            if "secret" not in list(players_DH[p].keys()) and done:
                done = False
                getKeyDH(p)
            elif done:
                if players_DH[p]["secret"] is None and done:
                    done = False
                    getKeyDH(p)
    if done:
        msg = {
            "done" : True,
        }
        print(players_DH)
        send(json.dumps(msg))

def getServerKeyDH(received):
    secret = random.randint(1,16)
    value = ( sharedBase**secret ) % sharedPrime
    data = received
    send(str(value))
    server_DH = (int(data)** secret) % sharedPrime

def getKeyDH(player):

    secret = random.randint(1,16)
    value = ( sharedBase**secret ) % sharedPrime
    msg = {
        "sendTo": player,
        "content":{
            "type": "client_DH",
            "content":{
                "from": my_name,
                "value": value
            }
        }
    }
    if player not in list(players_DH.keys()):
        players_DH[player]={
            "secret" : secret,
            "value" : None
        }
    else:
        players_DH[player]["secret"] = secret

    send(json.dumps(msg))

def saveValueDH(received):
    if received["from"] not in list(players_DH.keys()):
        players_DH[received["from"]]={
            "secret" : None,
            "value" : received["value"]
        }
    else:
        players_DH[received["from"]]["value"] = received["value"]


def calculateKeyDH():
    
    temp = {}
    global players_DH
    for player,content in players_DH.items():
        temp[player] = {"key": None}
        temp[player]["key"] = (content["value"]**content["secret"]) % sharedPrime
    
    players_DH = temp

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
BUFSIZ = 2048
ADDR = (HOST, PORT)
sharedBase = 5
sharedPrime = 131

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)
my_name = sys.argv[1]
send(my_name)
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
    

    
    