"""
Server with clients - chatroom (client side)
Author: Elad yeshayahou
The program is a server with multiple clients
"""
# importing the required modules
import subprocess
from socket import *
from threading import Thread
from tkinter import *
import math
import time
import sys

# creating a send_choices list
SEND_CHOICES = [
    ("Echo", "E"),
    ("Upload file", "F"),
    ("Send Privately", "S")
]

# creating a udp client socket to connect to server, setting it to be broadcast
client = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)  # UDP
client.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
find_port = False

print("----Waiting for connection----")
# if a port was found to bind to the server, exit the loop
while True:
    for port in range(37020, 40005):
        try:
            client.bind(("", port))
            find_port = True
            break
        except:
            continue
    if find_port:
        break

# receive password, port, host, and the names that are connected to the server when connecting to the server
while True:
    data, addr = client.recvfrom(1024)
    if data != "":
        data = data.decode()
        password, PORT, HOST, names = data.split(",")[0], int(data.split(",")[1]), data.split(",")[2], data.split(",")[
            3]
        break

ADDR = (HOST, PORT)
BUFSIZ = 1024
name = ""
start_client = True
equation = False


def user_quit():
    """
    function quits from the server, closing client_socket and root
    :return: None
    """
    try:
        client_socket.close()
        root.destroy()
        print("----CLIENT SHUT DOWN----")
    except:
        pass


def insert_to_list(msg_list, max_text):
    """
    function inserts into client's message list data received from server according to it's width
    :param msg_list: client's message list
    :param max_text: data received from the server
    :return:
    """
    while True:
        if (len(max_text)) > int(root_width / 9.5):
            msg_list.insert(END, max_text[:int(root_width / 9.5)])
            max_text = max_text[int(root_width / 9.5):]
        else:
            msg_list.insert(END, max_text)
            msg_list.see("end")
            break


def receive():
    """
    function handles receiving of messages from the server
    :return: None
    """
    run_once = 0
    global equation
    while True:
        try:

            # receiving messages from server
            msg = client_socket.recv(BUFSIZ).decode("utf8")

            # kick message
            if msg != "" and str(msg)[0] == "#":
                msg_list.insert(END, f"YOU HAVE BEEN KICKED BY {msg[msg.find(' ') + 1:]}")
                root.after(1500, user_quit)
                return

            if msg != "":

                if msg != "ADMIN SHUT DOWN":

                    # making sure it wont receive None
                    # making sure user is not uploading file or sending messages privately before signing in
                    if msg.find("You must sign in first") != -1:
                        if run_once == 0:
                            msg_list.insert(END, msg)
                            run_once = 1

                    else:
                        insert_to_list(msg_list, msg)

            else:
                break

            if msg == "Insert equation: ":

                # for CALC
                equation = True

            elif msg == "ADMIN SHUT DOWN":

                # END message
                msg_list.insert(END, "ADMIN HAS QUIT OR SHUT THE SERVER... GOODBYE !!")
                root.after(1000, user_quit)



        except OSError:

            # Possibly client has left the chat.
            user_quit()


def send(snd=None):
    """
    function handles sending of messages from client
    :param snd:
    :return: None
    """
    # modifying name, start_client, password, equation, msg to be global
    global name, start_client, password, equation, msg
    data = msg.get()

    # if needed to activate one of the radio buttons
    if rb_var.get() in list(commands.keys()):
        commands[rb_var.get()]()
        return True

    # if user hasn't send any data
    if not data:
        msg_list.insert(END, "you must enter enter a message !!!")
        return True

    # if name already taken
    if data in names.split("#"):
        msg_list.insert(END, "That name is already taken, please change your name")
        msg.set("")
        return True

    if start_client:

        # if this is the start
        name = data + ": "
        if password == "None":
            # Not ADMIN
            insert_to_list(msg_list, f'{data} Welcome to the chat room, enter QUIT to leave')
            msg_list.insert(END, "")
        else:
            # ADMIN
            insert_to_list(msg_list, f"{data} welcome to the chatroom! Enter QUIT to leave. You "
                                     f"are ADMIN. password: {password}")
            msg_list.insert(END, "")
        msg_list.see("end")
        start_client = False
        client_socket.send(f"{data} has joined the chat room".encode())



    elif data.upper() == "QUIT":

        # if the user quits, closing the root
        client_socket.send(f"{name}quit".encode())
        msg_list.insert(END, "SORRY TO SEE YOU GO. HOPE TO TO SEE YOU SOON AGAIN !!!")
        root.after(1000, user_quit)

    elif equation:

        # CALC --> uses for calculator
        try:
            msg_list.insert(END, eval(data))
        except:
            msg_list.insert(END, f"WRONG INPUT!")
        msg_list.see("end")
        equation = False


    else:

        # sending data to server
        try:
            client_socket.send(f"{name}{data}".encode())
        except (OSError, ConnectionAbortedError):
            msg_list.insert(END, "Connection with server lost :( ... now aborting")
            msg.set("")
            print("----Connection with server closed----")
            root.after(1500, user_quit)

    msg.set("")


def on_closing():
    """
    function closes root for client if he quits
    :return: None
    """
    client_socket.send(f"{name}quit".encode())
    msg_list.insert(END, "SORRY TO SEE YOU GO. HOPE TO TO SEE YOU SOON AGAIN")
    root.after(1000, user_quit)


def upload_file():
    """
    function uploads file according to user's request
    :return: None
    """
    file_name = msg.get() + (".txt" if ".txt" not in msg.get() else "")
    try:
        file = open(file_name, "r")
        if file.read() == "":
            msg_list.insert(END, "File is empty")
    except (FileNotFoundError, PermissionError):
        msg_list.insert(END, "File not found!!!!!")
        msg.set("")
    except OSError:
        msg_list.insert(END, "Plese enter file name in correct format")
        msg.set("")
    else:

        # sending each time the information by the client's socket buffer
        sent = 0
        file.seek(0)
        length = len(str(file.read()))
        file.seek(0)
        while sent < length:
            client_socket.send(f"UPLOAD{file.read(BUFSIZ)}".encode())
            sent += BUFSIZ
        client_socket.send("DONE".encode())
        msg.set("")


def send_echo_request():
    """
    function sends echo to client
    :return: None
    """
    text = msg.get()
    if text != "":
        try:
            client_socket.send(f"ECHO {text}".encode())
        except ConnectionResetError:
            msg_list.insert(END, "Connection with server lost :(")
        msg_list.see("end")
        entry_field.delete(0, "end")
    else:
        msg_list.insert(END, "you must enter enter a message !!!")
        msg.set("")
        return True
    msg.set("")


def send_to_client():
    """
    function sends to specific client that is connected to the server
    :return: None
    """
    text = msg.get()
    if text != "":
        try:
            if ":" not in text:
                msg_list.insert(END, "Please enter in correct format")
                msg.set("")
                return True

            client_socket.send(f"SEND TO {text[:text.find(':')]},{text[text.find(':') + 1:]}".encode())
        except ConnectionResetError:
            msg_list.insert(END, "Connection with server lost :(")
        msg_list.see("end")
        entry_field.delete(0, "end")
    else:
        msg_list.insert(END, "you must enter enter a message !!!")
        return True


# creating commands dictionary
commands = {
    "F": upload_file,
    "E": send_echo_request,
    "S": send_to_client
}

# creating the root for client side
root = Tk()
root.title("CHAT ROOM")
root_width = int(root.winfo_screenwidth() / 100 * 70)
root_height = int(root.winfo_screenheight() / 100 * 80)
root.minsize(height=root_height, width=root_width)
root.geometry(
    f"{root_width}x{root_height}+{int(root.winfo_screenwidth() / 2 - root_width / 2)}+" f"{int(root.winfo_screenheight() / 2 - root_height / 2)}")
root.config(bg='#ebebe0')

# creating the frame for the chat room, with scrollbar and StringVar
messages_canvas = Canvas(root)
msg = StringVar()  # For the messages to be sent.
msg.set("")
scrollbar = Scrollbar(messages_canvas)  # To navigate through past messages.
scrollbar.config(command=messages_canvas.yview)

# creating listbox that will contain the messages.
msg_list = Listbox(messages_canvas, height=12, width=int(root_width / 10), yscrollcommand=scrollbar.set,
                   font="Calibri 16 italic")
scrollbar.pack(side=RIGHT, fill=Y)
msg_list.pack(fill=BOTH, expand=YES)
messages_canvas.pack(fill=BOTH, expand=YES)
messages_canvas.config(scrollregion=messages_canvas.bbox("all"))

# creating entry field to enter the messages
entry_field = Entry(root, font="Calibri 16", textvariable=msg, width=40)
entry_field.bind("<Return>", send)
entry_field.pack()

# creating three options - SEND ECHO, UPLOAD FILE, SEND PRIVATELY with radio buttons
rb_var = StringVar()
rb_var.set(0)
for text, choice in SEND_CHOICES:
    rb = Radiobutton(root, font=("Arial", 15, 'bold'), text=text, variable=rb_var, value=choice, bg='#ebebe0')
    rb_var.set(0)
    rb.pack(anchor="w")

# creating frames for the buttons - send and clean choice
btn_frame = Frame(root, bg='#ebebe0')
send_button = Button(btn_frame, text="Send", font="Calibri 15 italic", command=send, bg='#03fc84',
                     activebackground='#03fc84')
send_button.pack(side='left', padx=10)
clean_button = Button(btn_frame, text="Clean choice", font="Calibri 15 italic", command=lambda: rb_var.set(0),
                      bg='#03fc84',
                      activebackground='#03fc84')
clean_button.pack(side='right', padx=10)
btn_frame.pack(expand=1, fill=Y, side='bottom')

# if user closes chatroom
root.protocol("WM_DELETE_WINDOW", on_closing)

# creating client socket
client_socket = socket(AF_INET, SOCK_STREAM)

while 1:

    # making sure the client waits for connection
    try:
        client_socket.connect(ADDR)
        print("----Connected to server successfully----")
        break
    except (ConnectionRefusedError, TimeoutError):
        continue

# creating thread for chatting with server
receive_thread = Thread(target=receive)
receive_thread.daemon = True
receive_thread.start()

# running the loop
root.mainloop()
