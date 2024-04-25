import base64
import json
import socket
import sys
import threading
import tkinter as tk
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

sys.path.append(str(Path(__file__).resolve().parent.parent))
from shared import CryptographyUtils, Packets


msgs_priv = {}

users = []
CURRENT_CHAT = 0  # 0 for global chat, index for private chat

HOST, PORT = "localhost", 12345


def save_username(window: tk.Tk, entry: tk.Entry) -> None:
    username = entry.get().strip()
    window.destroy()
    create_main_window(username)


def on_select(
    event: tk.Event,
    title_label: tk.Label,
) -> None:

    widget: tk.Widget = event.widget

    if not (selection := widget.curselection()):
        return

    selection = selection[0]
    value = widget.get(selection)

    if selection != 0:
        title_label.config(text=f"Private Chat - {value}")
    else:
        title_label.config(text="Global Chat")

    global CURRENT_CHAT
    CURRENT_CHAT = selection


def send_message(
    message_input: tk.Entry,
    public_keys: list[RSAPublicKey],
    private_key: RSAPrivateKey,
    text_box: tk.Text,
    username: str,
) -> None:
    global CURRENT_CHAT
    message = message_input.get()
    message_input.delete(0, tk.END)

    if not message:
        return

    if CURRENT_CHAT == 0:
        packet = Packets.MessagePacket(username=username, message=message)
        Packets.send_packet(sock, packet, private_key, public_keys)

    else:
        packet = Packets.MessagePacket(username=username, message=message, dm=True)
        public_key = public_keys[CURRENT_CHAT - 1]

        Packets.send_direct_message(sock, packet, private_key, public_key)

    text_box.insert(tk.END, f"{username}: {message}\n")


def receive_messages(
    sock: socket.socket,
    textbox: tk.Text,
    private_key: RSAPrivateKey,
    users_listbox: tk.Listbox,
    public_keys: list[RSAPublicKey],
    usernames: list[str],
    username: str,
    title_label: tk.Label,
):
    global CURRENT_CHAT
    while True:
        data = Packets.recv_with_length(sock)
        if not data:
            break

        data, signature = data[:-256], data[-256:]
        decrypted_data = CryptographyUtils.decrypt(data, private_key)

        json_decoded = json.loads(decrypted_data)

        match json_decoded["type"]:
            case Packets.PacketType.JOIN.value:
                if json_decoded["username"] not in usernames:
                    usernames.append(json_decoded["username"])

                pk = CryptographyUtils.deserialize_public_key(
                    base64.b64decode(json_decoded["public_key"])
                )
                if pk not in public_keys:
                    public_keys.append(pk)

                textbox.insert(
                    tk.END,
                    f"{json_decoded['username']} has joined the chat.\n",
                )

                users_listbox.insert(tk.END, json_decoded["username"])

            case Packets.PacketType.STATUS.value:
                if json_decoded["username"] not in usernames:
                    usernames.append(json_decoded["username"])
                    users_listbox.insert(tk.END, json_decoded["username"])

        index = usernames.index(json_decoded["username"])
        pk = public_keys[index]
        if not CryptographyUtils.verify(signature, data, pk):
            textbox.insert(
                tk.END,
                f"Invalid signature from {json_decoded['username']}\n",
            )

        match json_decoded["type"]:
            case Packets.PacketType.STATUS_REQUEST.value:
                status_packet = Packets.StatusPacket(username=username)
                Packets.send_direct_message(sock, status_packet, private_key, pk)

            case Packets.PacketType.MESSAGE.value:
                prefix = ""
                if json_decoded["dm"]:
                    if (
                        CURRENT_CHAT == 0
                        or usernames[CURRENT_CHAT - 1] != json_decoded["username"]
                    ):
                        prefix = "(DM) "
                else:
                    if CURRENT_CHAT:
                        prefix = "(GC) "

                textbox.insert(
                    tk.END,
                    f"{prefix}{json_decoded['username']}: {json_decoded['message']}\n",
                )

                if json_decoded["dm"]:
                    if json_decoded["username"] not in msgs_priv:
                        msgs_priv[json_decoded["username"]] = []

                    msgs_priv[json_decoded["username"]].append(
                        f"{prefix}{json_decoded['username']}: {json_decoded['message']}\n"
                    )

                else:
                    if "Global Chat" not in msgs_priv:
                        msgs_priv["Global Chat"] = []

                    msgs_priv["Global Chat"].append(
                        f"{prefix}{json_decoded['username']}: {json_decoded['message']}\n"
                    )

                if textbox.yview()[1] == 1.0:
                    textbox.yview_moveto(1.0)

            case Packets.PacketType.LEAVE.value:
                if json_decoded["username"] in usernames:
                    index = usernames.index(json_decoded["username"])
                    public_keys.pop(index)
                    usernames.remove(json_decoded["username"])

                textbox.insert(
                    tk.END,
                    f"{json_decoded['username']} has left the chat.\n",
                )

                users_listbox.delete(index + 1)
                users_listbox.select_set(0)
                CURRENT_CHAT = 0
                title_label.config(text="Global Chat")

                if textbox.yview()[1] == 1.0:
                    textbox.yview_moveto(1.0)

        if textbox.yview()[1] == 1.0:
            textbox.yview_moveto(1.0)


def on_closing(
    clients_public_keys: list[RSAPublicKey],
    public_key: RSAPublicKey,
    private_key: RSAPrivateKey,
    username: str,
    window: tk.Tk,
) -> None:
    packet = Packets.LeavePacket(
        username=username, public_key=CryptographyUtils.serialize_public_key(public_key)
    )
    Packets.send_packet(sock, packet, private_key, clients_public_keys)

    window.destroy()


def create_main_window(username: str) -> None:

    private_key, public_key = CryptographyUtils.generate_key_pair()
    usernames = []

    clients_public_keys = Packets.client_join(sock, username, public_key, private_key)

    main_window = tk.Tk()
    main_window.title("Chat")
    main_window.geometry("1200x800")

    users_frame = tk.Frame(main_window)
    users_frame.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.Y)

    label = tk.Label(users_frame, text="Users Online", font=("Arial", 12, "bold"))
    label.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

    users_listbox = tk.Listbox(
        users_frame,
    )
    users_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    users_listbox.bind("<<ListboxSelect>>", lambda event: on_select(event, title_label))

    frame_chat = tk.Frame(main_window)
    frame_chat.pack(side=tk.TOP, padx=10, pady=10, fill=tk.BOTH, expand=True)

    scollbar = tk.Scrollbar(frame_chat)
    scollbar.pack(side=tk.RIGHT, fill=tk.Y)

    title_label = tk.Label(frame_chat, text="Global Chat", font=("Arial", 12, "bold"))
    title_label.pack(fill=tk.X, padx=5, pady=5)

    textbox = tk.Text(frame_chat, yscrollcommand=scollbar.set)
    textbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scollbar.config(command=textbox.yview)

    frame_input = tk.Frame(main_window)
    frame_input.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

    message_input = tk.Entry(frame_input)
    message_input.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    message_input.bind(
        "<Return>",
        lambda _: send_message(
            message_input, clients_public_keys, private_key, textbox, username
        ),
    )

    enviar_button = tk.Button(
        frame_input,
        text="Send",
        command=lambda: send_message(
            message_input, clients_public_keys, private_key, textbox, username
        ),
    )
    enviar_button.pack(side=tk.RIGHT)

    receive_thread = threading.Thread(
        target=receive_messages,
        args=(
            sock,
            textbox,
            private_key,
            users_listbox,
            clients_public_keys,
            usernames,
            username,
            title_label,
        ),
        daemon=True,
    )

    receive_thread.start()
    users_listbox.insert(tk.END, "Global Chat")
    users_listbox.select_set(0)

    main_window.protocol(
        "WM_DELETE_WINDOW",
        lambda: on_closing(
            clients_public_keys, public_key, private_key, username, main_window
        ),
    )
    main_window.mainloop()


def fetch_users(users_listbox: tk.Listbox):

    users_listbox.insert(tk.END, "Global Chat")
    lst = ["User1", "User2", "User3"]

    users_listbox.select_set(0)

    for usr in lst:
        users_listbox.insert(tk.END, usr)


def create_username_window() -> None:
    username_window = tk.Tk()
    username_window.title("Enter Username")
    username_window.geometry("300x150")
    username_window.configure(bg="#f0f0f0")  # Cor de fundo

    label = tk.Label(
        username_window,
        text="Enter your username:",
        bg="#f0f0f0",
        font=("Arial", 12),
    )
    label.pack()

    entry = tk.Entry(username_window, font=("Arial", 12))
    entry.pack()

    entry.bind("<Return>", lambda _: save_username(username_window, entry))

    frame = tk.Frame(username_window, bg="#f0f0f0")
    frame.pack(pady=10)

    save_button = tk.Button(
        frame,
        text="Save",
        command=lambda: save_username(username_window, entry),
        font=("Arial", 12),
        bg="#4CAF50",
        fg="white",
        relief=tk.FLAT,
    )
    save_button.pack(side=tk.RIGHT, padx=5)

    username_window.mainloop()


# Configurações do cliente
if __name__ == "__main__":

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        try:
            create_username_window()

        except KeyboardInterrupt:
            sock.close()
        finally:
            sock.close()
