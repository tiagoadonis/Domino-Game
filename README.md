# Security - Online Domino Game

## Requirements

1. Software
    - Python3
    - termcolor
    - PyKCS11
    - cryptography
2. Hardware
    - Citizen Card Reader
    - Citizen Card

## How to run

1. OS details
    - Comment line 8 or 9 of file cc.py depending on OS
2. Server (Table Manager)
    - python3 server.py
3. Clients (Players) - Run at least 2 instances of client for the game to start!
    - python3 client.py [username] [Y/N]  -- ([Y/N] if the player is a cheater or not)
