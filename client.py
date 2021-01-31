#!/usr/bin/env python3
from symmetric_cipher import *
from asymmetric_cipher import *
from cc import *
from cryptography.hazmat.primitives import hashes
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from termcolor import colored
import pickle
import sys
import json
import random
import time
import base64
import secrets
import string
import os

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
my_points = 0
my_name= ""
nameInput = ""
players= []
srv_stock_empty = False
players_DH = {}
players_ciphers = {}
server_DH = 0
my_pos = 0
asym_ciphers = {}
game_state = {}
players_public_keys = {}
players_bit_commitments = {}
my_bit_commitment = {}
table_bit_commitment = {}
players_num_pieces = {}


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
                sendPseudoSign()
                print(colored("I won!!!!!!!!!","green"))
    elif msg["type"] == "server_DH":
        getServerKeyDH(msg["content"])
    elif msg["type"] == "setUpClientDH":
        setUpClientDH()
    elif msg["type"] == "client_DH":
        saveValueDH(msg["content"])
    elif msg["type"] == "calculate_DH":
        calculateKeyDH()
    elif msg["type"] == "setUpAsymCipher":
        setUpAsymCipher()
    elif msg["type"] == "savePlayerPublicKey":
        savePlayerPublicKey(msg["from"],msg["content"])
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
    elif msg["type"] == "createBitCommitment":
        createBitCommitment(msg["content"])
    elif msg["type"] == "receiveBitCommitment":
        receiveBitCommitment(msg["from"],msg["content"])
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
    elif msg["type"] == "rcvPlayerDraw":
        rcvPlayerDraw(msg['from'],msg['content'],msg['signature'])
    elif msg["type"] == "doneStock":
        setPlayersNumPieces()
        print("My stock: ",stock)
    elif msg["type"] == "play":
        play()
    elif msg["type"] == "rcvPlay":
        receivePlay(msg['from'],msg["content"])
    elif msg["type"] == "draw":
        draw(msg["content"])
    elif msg["type"] == "getting_pieces":
        points = gameAccountig(stock)
        sendPieces(msg["content"], msg["ip"], points)
    elif msg["type"] == "send_game_points":
        sendPoints()
    elif msg["type"] == "calculating_adv_points":
        correct = checkAdvPoints(msg["stock"], msg["points"])
        sendCheckingResult(correct)
    elif msg["type"] == "terminate_game":
        os._exit(1)
    return True
    
def sendCheckingResult(flag):
    msg = {
        "result": flag[0],
        "points": flag[1]
    }
    send(json.dumps(msg))

def checkAdvPoints(myStock, points):
    correct = [False, points]
    checkPoints = gameAccountig(myStock)
    if (checkPoints == points):
        correct = [True, checkPoints]
    return correct

def sendPieces(printToBeDone, ip, points):
    msg = {
        "from": my_name,
        "stock": str(stock),
        "points": points,
        "address": str(ip)
    }
    send(json.dumps(msg))

def save_players(content):
    #save other players names in order
    global my_pos
    i = 0 
    for name in content:
        if name != my_name:
            players.append([name, 0])
        else:
            my_pos = i
        i+=1

def num_pieces(content):
    global numPieces
    numPieces = content
    print("Number of pieces per player: "+str(numPieces))

def setUpAsymCipher():
    global my_asym_cipher
     
    my_asym_cipher = AsymmetricCipher(1024)
    serialized_pk = serializeBytes(my_asym_cipher.serializePublicKey())
    msg = {}
    for p in players:
        
        ciphered_play = players_ciphers[p[0]]["symcipher"].cipher(serialized_pk ,players_ciphers[p[0]]["symcipher"].key)
        dic = {
            "from": my_name,
            "content": serializeBytes(ciphered_play)
        }
        msg[p[0]] = dic
    send(json.dumps(msg))

def savePlayerPublicKey(from_p,content):
    ciphered = deserializeBytes(content)
    cipher = players_ciphers[from_p]["symcipher"]
    deciphered = SymmetricCipher.s_decipher(ciphered,cipher.key).decode('utf-8')

    players_public_keys[from_p] = AsymmetricCipher.loadPublicKey( deserializeBytes(deciphered))
    send(json.dumps({}))

def dstr_ciphered_stock(from_p,content):
    """Client Take / Not Take a piece from stock"""
    stockS = []
    if from_p is None:
        stockS = content	# Stock from server
    else:
        content = deserializeBytes(content)
        deciphered = players_ciphers[from_p]["symcipher"].decipher(content,players_ciphers[from_p]["symcipher"].key)
        
        deciphered = deciphered[:deciphered.find(bytes(']','utf-8'))+1]
        stockS = eval(deciphered)

    prob =random.randint(1,20) #random.randint(1,20)
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

        
        sendRandomPlayer(stockS)#Send to server to be routed to a random player

    else:
        dic = {
            "ndone": False,
            "ciphered_stock"  : stockS
        }
        send(str(json.dumps(dic))) # when finished send to server with flag ndone = False

def createBitCommitment(content):

    global table_bit_commitment
    global my_bit_commitment

    table_bit_commitment['r1'] = deserializeBytes(content['r1'])
    table_bit_commitment['bit_commitment'] = deserializeBytes(content['bit_commitment'])

    r1 = b''
    r2 = b''

    while r1 == r2:
        r1 = secrets.token_bytes(32)
        r2 = secrets.token_bytes(32)
    
    my_bit_commitment['r1'] = r1
    my_bit_commitment['r2'] = r2

    digest = hashes.Hash(hashes.SHA256())
    digest.update(r1)
    digest.update(r2)
    digest.update(bytes(str(ciphered_stock),'utf-8'))
    bit_commitment = digest.finalize()

    my_bit_commitment['bit_commitment'] = bit_commitment
    my_bit_commitment['ciphered_hand'] = ciphered_stock.copy()

    b = {
        "bit_commitment": serializeBytes(bit_commitment),
        "r1": serializeBytes(r1)
    }
    signature = my_asym_cipher.sign(json.dumps(b),my_asym_cipher.private_key)
    msg = {
        "bit_commitment" : b,
        "signature" : serializeBytes(signature)
    }
    send(json.dumps(msg))

def receiveBitCommitment(from_p,content):

    b = content['bit_commitment']
    signature = deserializeBytes(content['signature'])
    if AsymmetricCipher.validate_signature(signature,json.dumps(b), players_public_keys[from_p]):
        players_bit_commitments[from_p] = {
            "r1" : deserializeBytes(b['r1']),
            "bit_commitment" : deserializeBytes(b['bit_commitment'])
        }
        send(json.dumps({}))
    else:
        msg = {
            "failedSignatureValidation" : True
        }
        send(json.dumps(msg))

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
            pwd = str(random.randint(1,10000))
            
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
            if (from_p == players[0][0] and my_pos!=0) or (my_pos == 0 and from_p == my_name):
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

    if (from_p == players[0][0] and my_pos!=0) or (my_pos == 0 and from_p == my_name):
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
        deciphered = deciphered[:deciphered.find(bytes('}','utf-8'))+1]
        keys_dic = json.loads(deciphered.decode('utf-8').replace("'","\""))

    prob = random.randint(1,20)
    
    
    if len(keys_dic) != ((len(players)+1)*numPieces): #while the keys dictionary received isnt the right size repeat
        if prob == 1 and len(asym_ciphers) != numPieces: #create keys, send the public and save the private
            
            #key creation and insertion
            tuple_i = random.choice(temp_pseudo_stock)
            temp_pseudo_stock.remove(tuple_i)
            i = tuple_i[0]
            asym_cipher = AsymmetricCipher(2048)
            asym_ciphers[str(i)] = asym_cipher
            keys_dic[str(i)] = serializeBytes(asym_cipher.serializePublicKey())
            print("Put one public key")
        sendRandomPlayer(keys_dic)#Send to server to be routed to a random player

    else:
        dic = {
            "ndone": False,
            "public_keys"  : keys_dic
        }
        send(json.dumps(dic)) # when finished send to server with flag ndone = False

def sendPublicKeyDrawedPiece():

    global asym_cipher_drawed_piece
    key_dic = {}
    asym_cipher_drawed_piece = AsymmetricCipher(2048)
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
                    digest = hashes.Hash(hashes.SHA256())
                    digest.update(bytes(str(i),'utf-8'))
                    digest.update(key)
                    digest.update(bytes(t_k['piece'],'utf-8'))
                    pseudo_piece = digest.finalize()
                    if pseudo_piece == t[1]:
                        stock.append(t_k['piece'])
    
    send(json.dumps({}))

def getAndCheckDrawedPiece(content):
    deserialized_content = deserializeBytes(content)
    deciphered = asym_cipher_drawed_piece.decipher(deserialized_content,asym_cipher_drawed_piece.private_key)
    t_k = json.loads(deciphered.replace("'","\""))
    key = deserializeBytes(t_k['key'])


    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes(str(drawed_piece[0]),'utf-8'))
    digest.update(key)
    digest.update(bytes(t_k['piece'],'utf-8'))
    pseudo_piece = digest.finalize()

    if pseudo_piece == drawed_piece[1]:
        stock.append(t_k['piece'])
        msg = {
            "content" : "successfulDraw",
            "signature": serializeBytes(my_asym_cipher.sign("successfulDraw",my_asym_cipher.private_key))
        }
        send(json.dumps(msg))
    else:
        send(json.dumps({"error" : True}))

def rcvPlayerDraw(from_p,content,signature):

    global players_num_pieces
    signature = deserializeBytes(signature)

    if AsymmetricCipher.validate_signature(signature,content,players_public_keys[from_p]):
        players_num_pieces[from_p] += 1
        msg = {}

    else:

        msg = {
                "failedSignatureValidation" : True
            }
    send(json.dumps(msg))
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



def sendRandomPlayer(msg):  #ask the server to send the message to a random player choosen by me
    """Handles sending of messages"""

    random_p = random.choice(players)[0]
    letters=string.ascii_lowercase
    msg=str(msg)
    while len(msg)<7000:
        msg += random.choice(letters)
    
    ciphered = players_ciphers[random_p]["symcipher"].cipher(str(msg),players_ciphers[random_p]["symcipher"].key)
    dic = {
        "sendTo" : random_p,
        "content"  : serializeBytes(ciphered)
    }
    client_socket.send(bytes(json.dumps(dic), "utf8"))

def setPlayersNumPieces():

    global players_num_pieces

    for p in players:
        players_num_pieces[p[0]] = numPieces
    
    
def play():
    play = {}
    global game_state
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
                                        play['piece'] = {
                                            str(p[0]) : True,
                                            str(p[-1]): False,
                                        }
                                    else:          #if second number set to true others stay false to be attached later
                                        game_state[len(game_state)] = {
                                            str(p[0]) : False,
                                            str(p[-1]): True,
                                        }
                                        play['piece'] = {
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
                                play['piece'] = {
                                            "d1" : True,
                                            "d2" : False,
                                            "s1" : False,     
                                            "s2": False,
                                            str(d[0]): True,    
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
                                        play['piece'] = {
                                            str(p[0]) : True,
                                            str(p[-1]): False,
                                        }
                                        
                                    else:
                                        game_state[len(game_state)] = {
                                            str(p[0]) : False,
                                            str(p[-1]): True,
                                        }
                                        play['piece'] = {
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
                                play['piece'] = {
                                            "d1" : True,
                                            "d2" : False,
                                            "s1" : False,     
                                            "s2": False,
                                            str(d[0]): True,    
                                        }

                                print("Played: ", "("+d[0]+"-"+d[0]+")","\nMy stock: ",stock)
                            
                    if changed:# if any piece was attached set the respective position where it attached to true
                        game_state[k][n] = True
                        play['connection'] = {
                            "play" : k,
                            "connected" : n 
                        }
        
        if not played and not srv_stock_empty: #if wasnt able to play and server stock isnt empty ask to draw another piece
            #try draw
            send_msg = {
                "draw" : True
            }
            send(json.dumps(send_msg))
        else: 
            if len(stock) == 0:#if my stock is empty tell the server i won and send the last game_state
                sendPlayToAll(play,True)
            else: # wasnt able to play, send game state to server
                sendPlayToAll(play,False)
    else: #first play, choose random piece and attach its "connections" to the game state
        piece = random.choice(stock)
        stock.remove(piece)
        if piece[0] == piece[-1]:
            game_state[0] = {
                "d1" : False,
                "d2" : False,
                "s1" : False,
                "s2": False,
                str(piece[0]): True,  
            }
            play['piece'] = {
                "d1" : False,
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
            play['piece'] = {
                str(piece[0]): False,
                str(piece[-1]): False
            }
        print("Played: ", "("+piece[0]+"-"+piece[-1]+")","\nMy stock: ",stock)
        sendPlayToAll(play,False)
        #send(json.dumps(game_state))
    countPoints(my_name,game_state) # Calculate my points during game

def sendPlayToAll(play,win):
    if win:
        play["win"] = True
    
    signature = my_asym_cipher.sign(json.dumps(play),my_asym_cipher.private_key)
    msg = {
        "play": play,
        "signature" : serializeBytes(signature)
    }
    send(json.dumps(msg))


def draw(rcv_stock):

    global drawed_piece
    
    if len(rcv_stock) != 0: # if the stock received form the server isnt empty, take a piece and send the rest
        drawed_piece = rcv_stock[0]
        dic = {
                "piece_taken"  : rcv_stock[0]
            }
        print("Drawing a piece from the stock ")
        send(json.dumps(dic))
    else: #if the stock was empty update global variable
        srv_stock_empty = True

def countPoints(from_p, state):
    pnts = 0
    for n in state:
        if len(state[n]) == 2:
            for i in state[n]:
                if False == state[n][i]:
                    pnts += int(i)
        else : 
            if False in state[n].values():
                pnts += int(list(state[n])[4])
    if pnts % 5 == 0:
        if from_p != my_name:
            for i in players:
                if i[0] == from_p:
                    ind = players.index([from_p, i[1]])
                    players[ind][1] += pnts
        else:
            global my_points
            my_points += pnts
    #tmp = players
    #tmp.append([my_name, my_points])
    #print(tmp)

def sendPoints():
    tmp = players
    print(colored(str(my_name) + " got " + str(my_points) + " points during the round! (ME!)","green"))
    for p in players:
        print(colored(str(p[0]) + " got " + str(p[1]) + " points during the round!","yellow"))
    tmp.append([my_name, my_points])
    msg = {
        "from": my_name,
        "content": tmp
    }
    send(json.dumps(msg))

def receivePlay(from_p,content):

    play = content['play']
    signature = deserializeBytes(content['signature'])

    msg = {}
    global game_state 
    global players_num_pieces
    play_number = len(game_state)
    dic_4gs = {}
    if AsymmetricCipher.validate_signature(signature,json.dumps(play), players_public_keys[from_p]):
        if validatePlay(play):
        
            if len(game_state) == 0:
                for n,connected in play['piece'].items():
                    if connected:
                        dic_4gs[n] = True
                    else:
                        dic_4gs[n] = False
            else:
                for n,connected in play['piece'].items():
                    if connected:
                        dic_4gs[n] = True
                    else:
                        dic_4gs[n] = False
                
                game_state[play["connection"]["play"]][play["connection"]["connected"]] = True
            game_state[play_number] = dic_4gs
            countPoints(from_p, game_state)       # Conta os pontos durante o jogo (caso soma extremidades sejam multiplas de 5)
            players_num_pieces[from_p] -= 1

            if "win" in list(play.keys()):
                if players_num_pieces[from_p] == 0:

                    msg = {
                        "win" : True
                    }
                else:
                    msg = {}
                    print(from_p+" says he has won but I disagree")
        else:
            msg = {
                "invalidPlay" : True
            }
    else:
        msg = {
                "failedSignatureValidation" : True
            }
    send(json.dumps(msg))

def validatePlay(play):
    
    piece_json = play['piece'] 
    
    piece=""
    piece_list = [] 
    for key in piece_json.keys(): 
        piece_list.append(key) 
    if len(piece_list)==2:
        piece = piece_list[0]+"-"+piece_list[1]
    else:
        piece = piece_list[4]+"-"+piece_list[4]

    if inGameState(piece):
        print("Invalid play detected, tried to play a piece that was already played")
        return False
    
    if len(game_state)>0:
        connection_json = play['connection']
        
        play = connection_json['play']
        connected_to = connection_json['connected']
        
        if game_state[play][connected_to]:
            print("Invalid play detected, tried to attach to a piece that was already used")
            return False
    
    if piece in stock:
        print("Invalid play detected, tried to play a piece that is in my hand")
        return False
    return True

def getDoublePiece(n): #get first double piece available with the number n
    prob = random.randint(1,3) #cheating probability 
    for p in stock:
        if p.find(n+"-"+n) != -1:
            stock.remove(p)
            return p

    #cheat operation
    if (prob == 1 and cheater.lower() == 'y'):
        piece = (n+"-"+n)
        
        if (inGameState(piece) == False) and (piece not in stock):
            index = random.randint(0, len(stock)-1)
            stock.pop(index)
            print("I cheated! Shhhhh")
            return piece

    return None

def getPiece(n): #get first piece available with the number n 
    prob = random.randint(1,3) #cheating probability
    for p in stock:
        if p.find(n) != -1:
            stock.remove(p)
            return p
    
    #cheat operation
    if (prob == 1 and cheater.lower() == 'y'):
        
        for i in range(0,7):
            if int(n) > i:
                piece = (str(i)+"-"+str(n))
            else:
                piece = (str(n)+"-"+str(i))
            if (inGameState(piece) == False) and (piece not in stock):
                index = random.randint(0, len(stock)-1)
                stock.pop(index)
                print("I cheated! Shhhhh")
                return piece
    
    return None

# To detect if the piece exists on the game_state
def inGameState(piece):
    pieces = []
    keysGameState = list(game_state.keys())
    for key in keysGameState:
        result = game_state.get(key)    
        if len(list(result.keys())) == 2:
            lista = list(result.keys())
            elem1 = (lista.pop(0)).replace('\'', '')
            elem2 = (lista.pop(0)).replace('\'', '')
            pieces += [[str(elem1)+"-"+str(elem2)]]
        else:
            size = len(list(result.keys()))
            resultKeys = list(result.keys())
            elem = resultKeys.pop(size-1)
            pieces += [[str(elem)+"-"+str(elem)]]

    for p in pieces:
        newP = str(p).replace('\'', '')
        new2P = newP.replace(']', '')
        new3P = new2P.replace('[', '')
        if new3P == piece:
            return True

    return False

def gameAccountig(myStock):
    points = 0
    if (len(myStock) > 0):
        for piece in myStock:
            newPiece = str(piece).split("-")
            for p in newPiece:
                points += int(p)

    return points

def setUpClientDH():
    done = True
    for p in players:
        if p[0] not in list(players_DH.keys()) and done:
            done = False
            getKeyDH(p[0])
        elif done:
            if "secret" not in list(players_DH[p[0]].keys()) and done:
                done = False
                getKeyDH(p[0])
            elif done:
                if players_DH[p[0]]["secret"] is None and done:
                    done = False
                    getKeyDH(p[0])
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

def createPseudo(my_name):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes(my_name,'utf-8'))
    return digest.finalize()

def sendPseudo():    # Send Pseudo & Public Key
    msg = {
        "from": my_name,
        "pubKey": serializeBytes(getPublicKey())
    }
    send(json.dumps(msg))

def sendPseudoSign():
    msg = {
        "from": my_name,
        "sign": serializeBytes(signaturePseudo(my_name))
    }
    send(json.dumps(msg))


#----Sockets part----#
HOST = "127.0.0.1"
PORT = 1241
BUFSIZ = 32768
ADDR = (HOST, PORT)
sharedBase = 5
sharedPrime = 131

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

if (len(sys.argv) == 3):
    nameInput = sys.argv[1]
    my_name = serializeBytes(createPseudo(nameInput))
    if ( (sys.argv[2].lower() != "n") and (sys.argv[2].lower() != "y")):
        print("ERROR!!\nUSAGE: python client.py [username] [Y/N]\n[Y/N] - if the player is a cheater or not")
        sys.exit()
    else:
        cheater = sys.argv[2] #to identify a cheater player
else:
    print("ERROR!!\nUSAGE: python client.py [username] [Y/N]\n[Y/N] - if the player is a cheater or not")
    sys.exit()

sendPseudo()
main_thread = Thread(target=main)
main_thread.start()

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
    