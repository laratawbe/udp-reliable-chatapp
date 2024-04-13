import tkinter as tk
import socket
import threading
import hashlib
import random
from datetime import datetime

SEQUENCE_NUM_SIZE = 4
HEADER_SIZE = SEQUENCE_NUM_SIZE

PEER_IP = '127.0.0.1'
RECEIVE_PORT = 8000
SEND_PORT = 8080

def generate_checksum(sequence_num, data):
    # Generate SHA-256 checksum for concatenated components
    combined_data = f"{sequence_num}{data}"
    checksum = hashlib.sha256(combined_data.encode()).hexdigest()
    return checksum

def receive_messages(server_socket, chat_frame):
    last_ack_sent = 0  
    received_chunks = {}  # Dictionary to store received chunks

    while True:
        try:
            packet, peer_address = server_socket.recvfrom(65535)  # Receive entire packet
            sequence_num = int(packet[:SEQUENCE_NUM_SIZE])
            next_sequence_number = sequence_num
            data = packet[HEADER_SIZE:-64]
            received_checksum = packet[-64:].decode()  # Extract checksum from the end

            # Calculate checksum of received data
            computed_checksum = generate_checksum(sequence_num, data.decode())

            if received_checksum == computed_checksum:
                if sequence_num > last_ack_sent:  
                    # Send ACK back to sender
                    ack_message = f"{sequence_num}"
                    server_socket.sendto(ack_message.encode(), peer_address)

                    # Store the received chunk in the dictionary
                    received_chunks[sequence_num] = (data.decode(), peer_address)

                    # Check if we can process any contiguous chunks
                    while next_sequence_number in received_chunks:
                        # Process and print the chunk
                        message, _ = received_chunks[next_sequence_number]
                        display_message(chat_frame, message, received=True)
                        del received_chunks[next_sequence_number]  # Remove processed chunk
                        next_sequence_number += 1  # Move to the next expected sequence number

                    last_ack_sent = sequence_num
                else:
                    print(f"Received a retransmitted packet {sequence_num}. Reacking and Ignoring.")
                    ack_message = f"{sequence_num}"
                    server_socket.sendto(ack_message.encode(), peer_address)
                    last_ack_sent = sequence_num

            else:
                print(f"Received packet {sequence_num} with incorrect checksum. Discarding.")

        except socket.timeout:
            print("Receive timeout occurred.")

def send_message(server_socket, peer_address, message_entry, chat_frame):
    sequence_number = random.randint(1, 2**SEQUENCE_NUM_SIZE - 1)

    message = message_entry.get()

    if message == "HeymanStopman":
        print("Exiting...")
        return

    checksum = generate_checksum(sequence_number, message)

    packet = f"{sequence_number:0{SEQUENCE_NUM_SIZE}d}{message}{checksum}"
    server_socket.sendto(packet.encode(), peer_address)

    display_message(chat_frame, message, received=False)

    message_entry.delete(0, tk.END)

def display_message(chat_frame, message, received=False):
    time_stamp = datetime.now().strftime("%H:%M:%S")

    if received:
        message_text = f"{time_stamp} - Peer: {message}"
    else:
        message_text = f"{time_stamp} - You: {message}"

    message_label = tk.Label(chat_frame, text=message_text, wraplength=300, justify="left", bg="lightblue" if received else "lightgreen")
    message_label.pack(anchor="w", padx=10, pady=5)

def main():
    root = tk.Tk()
    root.title("Messaging App")

    chat_frame = tk.Frame(root, bg="white", width=400, height=300)
    chat_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    message_entry = tk.Entry(root, width=50)
    message_entry.pack(padx=10, pady=10, side=tk.LEFT, fill=tk.X, expand=True)

    send_button = tk.Button(root, text="Send", command=lambda: send_message(send_socket, send_address, message_entry, chat_frame))
    send_button.pack(padx=10, pady=10, side=tk.RIGHT)

    receive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receive_socket.bind((PEER_IP, RECEIVE_PORT))

    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send_address = (PEER_IP, SEND_PORT)

    receive_thread = threading.Thread(target=receive_messages, args=(receive_socket, chat_frame))
    receive_thread.start()

    root.mainloop()

if __name__ == "__main__":
    main()
