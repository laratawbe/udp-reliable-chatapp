import socket
import threading
import hashlib
import random

SEQUENCE_NUM_SIZE = 4
HEADER_SIZE = SEQUENCE_NUM_SIZE

PEER_IP = '127.0.0.1'
RECEIVE_PORT = 8080
SEND_PORT = 8000

def generate_checksum(sequence_num, data):
    # Generate SHA-256 checksum for concatenated components
    combined_data = f"{sequence_num}{data}"
    print("COMBINED DATA" , combined_data)
    checksum = hashlib.sha256(combined_data.encode()).hexdigest()
    return checksum

def receive_messages(server_socket):
    received_chunks = {}  # Dictionary to store received chunks
    # Expected sequence number of the next chunk to process

    while True:
        try:
            packet, peer_address = server_socket.recvfrom(65535)  # Receive entire packet
            sequence_num = int(packet[:SEQUENCE_NUM_SIZE])
            next_sequence_number = sequence_num
            data = packet[HEADER_SIZE:-64]
            received_checksum = packet[-64:].decode()  # Extract checksum from the end

            # Calculate checksum of received data
            computed_checksum = generate_checksum(sequence_num, data.decode())
            print(f"Computed Checksum: {computed_checksum}")
            print(f"Received Checksum: {received_checksum}")

            if received_checksum == computed_checksum:
                # Send ACK back to sender
                ack_message = f"{sequence_num}"
                server_socket.sendto(ack_message.encode(), peer_address)

                # Store the received chunk in the dictionary
                received_chunks[sequence_num] = data.decode()

                # Check if we can process any contiguous chunks
                while next_sequence_number in received_chunks:
                    # Process and print the chunk
                    print(f"Received from {peer_address}: {received_chunks[next_sequence_number]}")
                    del received_chunks[next_sequence_number]  # Remove processed chunk
                    next_sequence_number += 1  # Move to the next expected sequence number

                print(f"ACK {sequence_num} received by {peer_address}")
            else:
                print(f"Received packet {sequence_num} with incorrect checksum. Discarding.")

        except socket.timeout:
            print("Receive timeout occurred.")

def send_messages(server_socket, peer_address):
    sequence_number = random.randint(1, 2**SEQUENCE_NUM_SIZE - 1)

    while True:
        try:
            message = input("Enter message to send (type 'HeymanStopman' to exit): ")

            if message == "HeymanStopman":
                print("Exiting...")
                return

            # Calculate checksum for the entire message
            checksum = generate_checksum(sequence_number, message)

            # Create packet with sequence number, checksum, and data
            packet = f"{sequence_number:0{SEQUENCE_NUM_SIZE}d}{message}{checksum}"
            server_socket.sendto(packet.encode(), peer_address)
            print(f"Sent packet {sequence_number} to {peer_address}")

            server_socket.settimeout(2)
            try:
                ack_packet, ack_peer_address = server_socket.recvfrom(65535)  
                ack_sequence_num = int(ack_packet.decode())

                if ack_sequence_num == sequence_number and ack_peer_address == peer_address:
                    print(f"ACK {sequence_number} received from {peer_address}")
                    sequence_number += 1

            except socket.timeout:
                print("Timeout occurred. Retransmitting...")
        except KeyboardInterrupt:
            print("Exiting...")
            break

def main():
    receive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receive_socket.bind((PEER_IP, RECEIVE_PORT))

    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send_address = (PEER_IP, SEND_PORT)

    receive_thread = threading.Thread(target=receive_messages, args=(receive_socket,))
    receive_thread.start()

    try:
        send_messages(send_socket, send_address)
    finally:
        receive_socket.close()
        send_socket.close()
        receive_thread.join()

    print("Program terminated.")

if __name__ == "__main__":
    main()
