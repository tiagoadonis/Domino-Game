#!/usr/bin/env python3
from symmetric_cipher import *
from asymmetric_cipher import *
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import sys
import json
import random
import time
import base64

# variables
numPieces = 0
stock = []
pseudo_stock = []
temp_pseudo_stock = []
ciphered_stock = []
pseudo_stock_keys = {}
drawed_piece = None
asym_cipher_drawed_piece = None
nRound = 0
points = 0
my_name= ""
players= []
srv_stock_empty = False
players_DH = {}
players_ciphers = {}
server_DH = 0
my_pos = 0
asym_ciphers = {}

def main():
    """Main function"""
    nerror = True
    while nerror:
        try:
            a = receive()
            msg = json.loads(a)
            
            nerror = choose(msg)
            
        except OSError:  # Possibly client has left the chat.
            break

def choose(msg):
    global ciphered_stock
    if msg["type"] == "print":
        print(msg["content"])
        if msg["content"].find("The winner is") != -1:
            if msg["content"].find(my_name)!=-1:
                print("I won!!!!!!!!!")
            print("My stock: ", stock)
            
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
        return False
    elif msg["type"] == "players_info":
        save_players(msg["content"])
    elif msg["type"] == "numPieces":
        num_pieces(msg["content"])
    elif msg["type"] == "rcvPseudoStock":
        rcv_pseudo_stock(msg["content"])
    elif msg["type"] == "dstrCipheredStock":
        if "from" in list(msg.keys()):
            dstr_ciphered_stock(msg["from"],msg["content"])
        else:
            dstr_ciphered_stock(None,msg["content"])
    elif msg["type"] == "returnCipherStockKeys":
        returnCipherKeys()
    elif msg["type"] == "returnCipherPieceKey":
        returnCipherPieceKey(msg["content"])
    elif msg["type"] == "decipherStock":
        decipherStock(msg['from'],msg['content'])
    elif msg["type"] == "decipherDrawPiece":
        decipherDrawPiece(msg['from'],msg['content'])
    elif msg["type"] == "insertPublicKeys":
        if "from" in list(msg.keys()):
            sendPublicKeys(msg['from'],msg['content'])
        else:
            sendPublicKeys(None,msg['content'])
    elif msg["type"] == "insertPublicKeyDrawedPiece":
        sendPublicKeyDrawedPiece()
    elif msg["type"] == "decipherPieces":
        getAndCheckPieces(msg['content'])
    elif msg["type"] == "decipherPseudoDrawPiece":
        getAndCheckDrawedPiece(msg['content'])
    elif msg["type"] == "doneStock":
        print("My stock: ",stock)
    elif msg["type"] == "game_state":
        play(msg["content"])
    elif msg["type"] == "draw":
        draw(msg["content"])
    
    return True
    

def save_players(content):
    #save other players names in order
    global my_pos
    i = 0 
    for name in content:
        if name != my_name:
            players.append(name)
        else:
            my_pos = i
        i+=1

def num_pieces(content):
    global numPieces
    numPieces = content
    print("Number of pieces per player: "+str(numPieces))

def dstr_ciphered_stock(from_p,content):
    """Client Take / Not Take a piece from stock"""
    stockS = []
    if from_p is None:
        stockS = content	# Stock from server
    else:
        content = deserializeBytes(content)
        deciphered = players_ciphers[from_p]["symcipher"].decipher(content,players_ciphers[from_p]["symcipher"].key)
        stockS = eval(deciphered)

    arr = [1, 0, 0, 0, 0] # 20% probability of taking a piece
    prob = random.choice(arr)
    global ciphered_stock
    global numPieces
   
    if len(stockS) != (28 - ((len(players)+1)*numPieces)): #while the stock received from the server isnt the right size repeat
        if prob == 1 and len(ciphered_stock) != numPieces: #take a piece
            
            ciphered_stock.append(stockS[0])
            temp = stockS[1:]
            stockS = temp
            print("Took a piece")
            
            
        else:
            p = random.randint(0, 1) # 50% probability of swaping a piece
            if p == 1 and len(ciphered_stock) == numPieces:
                chg = random.choice(ciphered_stock)
                b = []
                for a in ciphered_stock:
                    if a != chg:
                        b.append(a)
                    else:
                        b.append(stockS[0])
                        stockS = stockS[1:]
                        stockS.append(a)
                ciphered_stock = b
                print("Swap a piece")

        
        sendRandomPlayerv2(stockS)#Send to server to be routed to a random player

    else:
        dic = {
            "ndone": False,
            "ciphered_stock"  : stockS
        }
        send(str(json.dumps(dic))) # when finished send to server with flag ndone = False

def rcv_pseudo_stock(content):
    
    
    if len(content[0]) == 2:
        content = deserializePseudo(content)
    else:
        content = deserializeStock(content)
    l_pwd = [1]
    pwd = 1
    ciphered = b''
    sym_cipher = SymmetricCipher("124")#random class to initialize sym_cipher

    ciphered_stock = []

    for c in content:
        while pwd in l_pwd or ciphered in list(pseudo_stock_keys.keys()):
            pwd = str(random.randint(1,100))
            
            sym_cipher = SymmetricCipher(str(pwd))
            if not isinstance(c,bytes):
                c = str(c)
            ciphered = sym_cipher.cipher(c,sym_cipher.key)

            
        pseudo_stock_keys[ciphered] = sym_cipher.key
        ciphered_stock.append(ciphered)

    msg = {
        "pseudo_randomized": serializeStock(ciphered_stock) 
    }
    send(json.dumps(msg))

def returnCipherKeys():
    #serialize pseudo_stock_keys and send to server
    p = serializePseudoCipherKeys()
    send(json.dumps(p))

def returnCipherPieceKey(content):
    msg = {
        "key" : serializeBytes(pseudo_stock_keys[deserializeBytes(content)])
    }
    send(json.dumps(msg))

def decipherStock(from_p,ciphers_keys):
    global temp_pseudo_stock
    global pseudo_stock
    for serialcipher in list(ciphers_keys.keys()):
        if serialcipher in ciphered_stock:#test which are in the stock
            serialkey = ciphers_keys[serialcipher]
            #decipher those on stock 
            ciphered = deserializeBytes(serialcipher)
            key = deserializeBytes(serialkey)
            deciphered = SymmetricCipher.s_decipher(ciphered,key)
            ciphered_stock.remove(serialcipher)
            if (from_p == players[0] and my_pos!=0) or (my_pos == 0 and from_p == my_name):
                deciphered = eval(deciphered)
                pseudo_stock.append(deciphered)
            else:
                serialdeciphered = serializeBytes(deciphered)
                ciphered_stock.append(serialdeciphered)

    temp_pseudo_stock = pseudo_stock.copy()
    send(json.dumps({}))

def decipherDrawPiece(from_p,cipher_key):
    
    global drawed_piece
    ciphered = deserializeBytes(drawed_piece)
    key = deserializeBytes(cipher_key)
    deciphered = SymmetricCipher.s_decipher(ciphered,key)

    if (from_p == players[0] and my_pos!=0) or (my_pos == 0 and from_p == my_name):
        drawed_piece = eval(deciphered)
    else:
        drawed_piece = serializeBytes(deciphered)

    send(json.dumps({}))

def sendPublicKeys(from_p,content):
 
    global asym_ciphers
    global numPieces
    keys_dic = {}
    if from_p is None:
        keys_dic = content	# keys_dic from server
    else:
        content = deserializeBytes(content)
        deciphered = players_ciphers[from_p]["symcipher"].decipher(content,players_ciphers[from_p]["symcipher"].key)
        keys_dic = json.loads(deciphered.decode('utf-8').replace("'","\""))

    arr = [1, 0, 0, 0, 0] # 20% probability of putting a public key
    prob = random.choice(arr)
    
   
    if len(keys_dic) != (28 - ((len(players)+1)*numPieces)): #while the keys dictionary received isnt the right size repeat
        if prob == 1 and len(asym_ciphers) != numPieces: #create keys, send the public and save the private
            
            #key creation and insertion
            tuple_i = random.choice(temp_pseudo_stock)
            temp_pseudo_stock.remove(tuple_i)
            i = tuple_i[0]
            asym_cipher = AsymmetricCipher(1024)
            asym_ciphers[str(i)] = asym_cipher
            keys_dic[str(i)] = serializeBytes(asym_cipher.serializePublicKey())
            print("Put one public key")
        sendRandomPlayerv2(keys_dic)#Send to server to be routed to a random player

    else:
        dic = {
            "ndone": False,
            "public_keys"  : keys_dic
        }
        send(json.dumps(dic)) # when finished send to server with flag ndone = False

def sendPublicKeyDrawedPiece():

    global asym_cipher_drawed_piece
    key_dic = {}
    asym_cipher_drawed_piece = AsymmetricCipher(1024)
    key_dic[drawed_piece[0]] = serializeBytes(asym_cipher_drawed_piece.serializePublicKey())
    msg = {
        "public_key" : key_dic
    }
    send(json.dumps(msg))

def getAndCheckPieces(content):

    global stock
    for i,a_c in asym_ciphers.items():
        my_pk = serializeBytes(a_c.serializePublicKey())
        if my_pk in list(content.keys()):
            deciphered = a_c.decipher(deserializeBytes(content[my_pk]),a_c.private_key)
            t_k = json.loads(deciphered.replace("'","\""))
            #verify
            key = deserializeBytes(t_k['key'])
            
            for t in pseudo_stock:
                if t[0] == int(i):
                    deciphered_piece = SymmetricCipher.s_decipher(t[1],key).decode('utf-8')
                    if deciphered_piece == t_k['piece']:
                        stock.append(deciphered_piece)
    
    send(json.dumps({}))

def getAndCheckDrawedPiece(content):
    deserialized_content = deserializeBytes(content)
    deciphered = asym_cipher_drawed_piece.decipher(deserialized_content,asym_cipher_drawed_piece.private_key)
    t_k = json.loads(deciphered.replace("'","\""))
    key = deserializeBytes(t_k['key'])

    deciphered_piece = SymmetricCipher.s_decipher(drawed_piece[1],key).decode('utf-8')
    if deciphered_piece == t_k['piece']:
        stock.append(deciphered_piece)
        send(json.dumps({}))
    else:
        send(json.dumps({"error" : True}))

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
        "sendTo" : random.choice(players),
        "stock"  : stock_temp
    }
    client_socket.send(bytes(json.dumps(dic), "utf8"))

def sendRandomPlayerv2(msg):  #ask the server to send the message to a random player choosen by me
    """Handles sending of messages"""

    random_p = random.choice(players)

    ciphered = players_ciphers[random_p]["symcipher"].cipher(str(msg),players_ciphers[random_p]["symcipher"].key)
    dic = {
        "sendTo" : random_p,
        "content"  : serializeBytes(ciphered)
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
                                    print("Played: ", "("+p[0]+"-"+p[-1]+")","\nMy stock: ",stock)
                                    
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
                                print("Played: ", "("+d[0]+"-"+d[0]+")","\nMy stock: ",stock)

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

                                    print("Played: ", "("+p[0]+"-"+p[-1]+")","\nMy stock: ",stock)
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

                                print("Played: ", "("+d[0]+"-"+d[0]+")","\nMy stock: ",stock)
                            
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
        print("Played: ", piece,"\nMy stock: ",stock)
        send(json.dumps(game_state))

def draw(rcv_stock):

    global drawed_piece
    
    if len(rcv_stock) != 0: # if the stock received form the server isnt empty, take a piece and send the rest
        drawed_piece = rcv_stock[0]
        dic = {
                "piece_taken"  : rcv_stock[0]
            }
        print("Drawing a piece from the stock, ")
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
    global players_ciphers

    for player,content in players_DH.items():
        temp[player] = {"key": None}
        temp[player]["key"] = (content["value"]**content["secret"]) % sharedPrime
    
    players_DH = temp
    temp = {}
    for player,content in players_DH.items():
        temp[player] = {"symcipher": None}
        temp[player]["symcipher"] = SymmetricCipher(str(players_DH[player]["key"]))

    players_ciphers = temp

def serializeBytes(bit):
    return base64.encodebytes(bit).decode("ascii")
    
def deserializeBytes(str):
    return base64.decodebytes(str.encode("ascii"))

def serializeStock(rcv_stock):
    send_stock = []
    for i in range(len(rcv_stock)):
        send_stock.append(serializeBytes(rcv_stock[i]))

    return send_stock

def deserializeStock(rcv_stock):
    send_stock = []
    for i in range(len(rcv_stock)):
        send_stock.append(deserializeBytes(rcv_stock[i]))
            
    return send_stock
    
def deserializePseudo(rcv_pseudo):
    send_stock = []
    for i in range(len(rcv_pseudo)):
        send_stock.append((rcv_pseudo[i][0],deserializeBytes(rcv_pseudo[i][1])))
   
    return send_stock

def serializePseudoCipherKeys():
    serialized = {}
    for c in list(pseudo_stock_keys.keys()):
        serialized[serializeBytes(c)] = serializeBytes(pseudo_stock_keys[c])
    
    return serialized


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
BUFSIZ = 32768
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
    

    
    