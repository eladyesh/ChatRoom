"""
Server with clients - chatroom (server side)
Author: Elad yeshayahou
The program is a server with multiple clients
"""
# importing the required modules
import random
import time
from select import select
import socket
from datetime import datetime


def get_open_port():
    """
    function gets open port available
    :return: open port
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port


# creating HOST, PORT, initiating server_socket
# creating 3 dictionaries to keep track of client time, and name
HOST = ""
PORT = get_open_port()
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
spam_client = {}
client_time = []
client_addr = {}
server_time = time.time()
initial_port = 37020
DAILY_QUOTE = ["When you have a dream, you’ve got to grab it and never let go.",
               "Nothing is impossible. The word itself says I’m possible!",
               "The bad news is time flies. The good news is you’re the pilot.",
               "Life has got all those twists and turns. You’ve got to hold on tight and off you go",
               "Keep your face always toward the sunshine, and shadows will fall behind you.",
               "Success is not final, failure is not fatal: it is the courage to continue that counts"]


def send_passport(port, password):
    """
    send udp packets with the password (for admin) and port (for connection)
    :param port: the port of the server.
    :param password: password of admin or None if not admin.
    return: None
    """
    global initial_port
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    data = f"{password},{port},{socket.gethostbyname(socket.gethostname())},{'#'.join(list(client_addr.keys()))}"
    udp_sock.sendto(data.encode(), ('<broadcast>', initial_port))
    initial_port += 1
    udp_sock.settimeout(0.2)
    if initial_port == 40005:
        initial_port = 37020


def broadcast(writables, msg):
    """
    function broadcasts to all sockets connected to the server
    :param writables: writable sockets
    :param msg: the message needed to be broadcast
    :return: None
    """
    for sockobj in writables:
        try:
            sockobj.send(msg.encode())
        except (OSError, ValueError):
            continue


def remove_from_lists(sock, read_sockets, client_time, write_sockets, spam_client, client_addr):
    """
    function removes the socket from all the possible lists and dictionaries it's in
    :param sock: the socket connected to the server
    :param read_sockets: readable sockets
    :param client_time: the client time's till wake up call (list)
    :param write_sockets: writable sockets
    :param spam_client: the client dictionary for spam to wake up
    :param client_addr: client dictionary, save clients_name as key and address by value
    :return: None
    """

    sock.close()
    read_sockets.remove(sock)
    client_time.pop(write_sockets.index(sock))
    write_sockets.remove(sock)
    if sock in client_addr.values():
        client_addr.pop(list(client_addr.keys())[list(client_addr.values()).index(sock)])
    spam_client.pop(sock)


def handle_connections():
    """
    the main function, handles all the sockets.
    :return: True to get out.
    """

    # creating the lists of sockets
    read_sockets, write_sockets = [], []

    # binding the server to host and port
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    server_socket.setblocking(0)
    mainsocks = [server_socket]

    # creating variables to keep track of client's uploading, kicking, ending server
    end_server = False
    kick = False
    run_once = 0

    read_sockets += mainsocks
    password = random.randint(10000, 100000)
    while True:

        # creates a new folders for the pictures if not exist
        readables, writeables, exceptions = select(read_sockets, write_sockets, [], 0)

        if not writeables:
            # if ADMIN
            send_passport(PORT, password)
        else:
            # all the other users
            send_passport(PORT, None)

        for sock in readables:
            if sock in mainsocks:

                # accepting new clients to the server
                newsock, address = sock.accept()
                newsock.send("what is your name?".encode())
                spam_client.update({newsock: time.time()})
                kick = False

                # updating time for the client, adding to read_sockets and write_sockets
                client_time.append(10)
                c_time = time.time()
                read_sockets.append(newsock)
                write_sockets.append(newsock)

            else:

                try:

                    # receiving information from client
                    data = sock.recv(1024).decode('utf8')

                    # making sure client doesn't upload file before signing in
                    if data.find("UPLOAD") != -1 and sock not in client_addr.values():
                        sock.send("You must sign in first".encode())
                        continue

                    # inputting name as key and socket by value
                    if data[:data.find("has")] not in list(client_addr.keys()) and len(
                            data[data.find("has"):].split(" ")) >= 4 and data.find("UPLOAD") == -1:
                        client_addr[data[:data.find("has")][:-1]] = sock
                        print(f"----CLIENT {sock.getpeername()} has joined----")

                    # updating time
                    spam_client[sock] = time.time()

                    try:

                        # getting admin
                        if id(sock) == id(writeables[0]):
                            admin = list(client_addr.keys())[list(client_addr.values()).index(sock)]

                    except ValueError:
                        if data.upper() != "QUIT":
                            sock.send("You must sign in first".encode())
                            break

                except ConnectionResetError:

                    # closing client, removing from read_sockets, writeables
                    print(f"----CLIENT  {sock.getpeername()}  LEFT----")
                    remove_from_lists(sock, read_sockets, client_time, write_sockets, spam_client, client_addr)
                    continue

                if data[data.find(":") + 2:].upper() == "END":

                    # if there is an attempt of ending the chatroom, sending password to close the server
                    end_server = True
                    sock.send("Password to close the server: ".encode())

                elif data[data.find(":") + 2:].upper() == "CALC":

                    # a calculator --> the user enters CALC and an equation and the server sends an answer
                    sock.send("Insert equation: ".encode())

                elif data[:7] == "SEND TO":

                    # sending privately message to client
                    send_to, message = data[8:].split(",")[0].strip(), data[8:].split(",")[1]
                    if send_to in client_addr.keys():
                        writeables[writeables.index(client_addr.get(send_to))] \
                            .send(f"{list(client_addr.keys())[list(client_addr.values()).index(sock)]} sent you "
                                  f"privately: {message}".encode())
                    else:
                        sock.send(f"{send_to} is not in the chatroom".encode())

                elif data[data.find(":") + 2:].upper() == "TIME":

                    # TIME ---> returns server local time
                    sock.send(f"server's local time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".encode())

                elif data[data.find(":") + 2:].upper() == "CLIENT ELAPSED TIME":

                    # CLIENT ELAPSED TIME ---> returns the amount of time the client exists
                    sock.send(f"client elapsed time {float(str(time.time() - c_time)[:-12])} seconds".encode())

                elif data[data.find(":") + 2:].upper() == "SERVER ELAPSED TIME":

                    # SERVER ELAPSED TIME --> returns the amount of time the server exists
                    sock.send(f"server elapsed time {float(str(time.time() - server_time)[:-12])} seconds".encode())

                elif data[data.find(":") + 2:].upper() == "QUIT":

                    # broadcasting the client has left
                    broadcast(writeables,
                              f"CLIENT {list(client_addr.keys())[list(client_addr.values()).index(sock)]} left")
                    print(f"----CLIENT {sock.getpeername()} left----")

                    # if user is admin, removing him and giving admin to the next user
                    if list(client_addr.keys())[list(client_addr.values()).index(sock)] == admin:
                        remove_from_lists(sock, read_sockets, client_time, write_sockets, spam_client, client_addr)
                        if write_sockets:
                            write_sockets[0].send(
                                f"Admin has left, You are now admin, your password is {password}".encode())
                            try:
                                admin = list(client_addr.keys())[list(client_addr.values()).index(write_sockets[0])]
                            except ValueError:
                                pass
                    else:
                        remove_from_lists(sock, read_sockets, client_time, write_sockets, spam_client, client_addr)
                    continue

                elif data[:4] == "ECHO":

                    # sending echo request
                    sock.send(f"ECHO request : {data[4:]}".encode())

                elif data.find("UPLOAD") != -1:

                    # uploading file
                    if run_once == 0:
                        broadcast(writeables,
                                  f"Uploading file by {list(client_addr.keys())[list(client_addr.values()).index(sock)]}")
                        run_once = 1
                    broadcast(writeables, data.replace("UPLOAD", "").replace("DONE", ""))

                    if data.find("DONE") != -1:
                        run_once = 0

                elif data[data.find(":") + 2: data.find(":") + 6].upper() == "KICK":

                    # kicking user
                    kick_name = data[data.find("kick") + 5:]
                    kick = True
                    remove_from_server = list(client_addr.keys())[list(client_addr.values()).index(sock)]
                    sock.send(f"Password to kick {kick_name}: ".encode())

                elif data[data.find(":") + 2:].upper() == "ONLINE":

                    # sends how many people are connected to the server
                    sock.send(f"The people online: {', '.join([key for key in client_addr.keys()])}".encode())

                elif data[data.find(":") + 2:].upper() == "QUOTE":

                    # sending quote of the day
                    sock.send(random.choice(DAILY_QUOTE).encode())

                elif end_server:

                    # an attempt of ending the meeting
                    if data.find(str(password)) >= 0:

                        # if the right password
                        for sock in writeables:
                            # close all the sockets with an announcement
                            sock.send("ADMIN SHUT DOWN".encode())
                            remove_from_lists(sock, read_sockets,
                                              client_time, write_sockets, spam_client, client_addr)

                        print("----ADMIN SHUTDOWN----")
                        return True
                    else:
                        sock.send("WRONG PASSWORD!".encode())
                        end_server = False
                        print("----WRONG PASSWORD----")
                        continue


                elif kick:
                    kick = False

                    # if password is true, kicking the user and broadcasting that the user has been kicked
                    if data.find(str(password)) >= 0:
                        if kick_name in client_addr.keys():

                            for socket in writeables:
                                if socket.getpeername() == client_addr[kick_name].getpeername():

                                    # kicking the user, broadcasting that he has been kicked
                                    socket.send(f"#kick {remove_from_server}".encode())
                                    broadcast(writeables, f"{kick_name} has been kicked by {remove_from_server}")
                                    print(f"----CLIENT  {socket.getpeername()}  has been kicked----")
                                    remove_from_lists(socket, read_sockets,
                                                      client_time, write_sockets, spam_client, client_addr)

                                    # if user is admin, passing the admin to the next socket in the list
                                    if kick_name == admin and write_sockets:
                                        write_sockets[0].send(f"Admin has been kicked by {remove_from_server},"
                                                              f" You are now admin, your password is {password}".encode())

                                        try:
                                            admin = list(client_addr.keys())[
                                                list(client_addr.values()).index(write_sockets[0])]
                                        except ValueError:
                                            pass
                                    break

                        else:
                            kick = False
                            sock.send(f"{kick_name} not in chatroom".encode())

                    else:
                        # if user password is wrong
                        sock.send("WRONG PASSWORD!".encode())
                        kick = False
                        print("----WRONG PASSWORD----")
                        continue
                else:

                    # broadcasting to all clients
                    if data != "quit" and data.find("UPLOAD") == -1:
                        broadcast(writeables, data)

        for client in spam_client:

            # spamming clients if the are not wake
            if time.time() - spam_client[client] > client_time[write_sockets.index(client)]:
                try:
                    # sending wake up call, updating client time
                    spam_client.update({client: time.time()})
                    client.send("WAKE UP!".encode())
                    client_time[write_sockets.index(client)] += 60
                except OSError:
                    continue


# starting the server
print("----STARTING SERVER----")
handle_connections()
server_socket.close()
