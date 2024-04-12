import socket
import threading
import hashlib

SEQUENCE_NUM_SIZE = 4
HEADER_SIZE = SEQUENCE_NUM_SIZE
MSS = 2000  # Maximum Segment Size
MAX_DATA_SIZE = 1932  # Max size for data in each packet

PEER_IP = '127.0.0.1'
RECEIVE_PORT = 8000
SEND_PORT = 8080

def generate_checksum(sequence_num, data):
    # Generate SHA-256 checksum for concatenated components
    combined_data = f"{sequence_num}{data}"
    # print("COMBINED DATA" , combined_data)
    checksum = hashlib.sha256(combined_data.encode()).hexdigest()
    return checksum

def receive_messages(server_socket):
    received_chunks = {}  # Dictionary to store received chunks
    next_sequence_number = 1  # Expected sequence number of the next chunk to process

    while True:
        try:
            packet, peer_address = server_socket.recvfrom(MSS)
            sequence_num = int(packet[:SEQUENCE_NUM_SIZE])
            data = packet[HEADER_SIZE:-64]
            received_checksum = packet[-64:].decode()  # Extract checksum from the end

            # Calculate checksum of received data
            computed_checksum = generate_checksum(sequence_num, data.decode())
            # print(f"Computed Checksum: {computed_checksum}")
            # print(f"Received Checksum: {received_checksum}")

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

                # print(f"Received ACK {sequence_num} from {peer_address}")
            # else:
                # print(f"Received packet {sequence_num} with incorrect checksum. Discarding.")

        except socket.timeout:
            print("Receive timeout occurred.")

def send_messages(server_socket, peer_address):
    sequence_number = 1

    while True:
        try:
            message = input("Enter message to send (type 'HeymanStopman' to exit): ")

            if message == "HeymanStopman":
                print("Exiting...")
                return

            message_chunks = [message[i:i + MAX_DATA_SIZE] for i in range(0, len(message), MAX_DATA_SIZE)]

            for i, chunk in enumerate(message_chunks):
                count = 0
                while count < 3:  # Retry loop for retransmission
                    # Create packet with sequence number, checksum, and data
                    checksum = generate_checksum(sequence_number, chunk)
                    packet = f"{sequence_number:0{SEQUENCE_NUM_SIZE}d}{chunk}{checksum}"
                    server_socket.sendto(packet.encode(), peer_address)
                    # print(f"Sent packet {sequence_number} to {peer_address}")
                    # print("Packet sent", packet, "Checksum sent", checksum, "\n length of packet", len(packet))
                    server_socket.settimeout(2)
                    try:
                        ack_packet, ack_peer_address = server_socket.recvfrom(MSS)
                        ack_sequence_num = int(ack_packet.decode())

                        if ack_sequence_num == sequence_number and ack_peer_address == peer_address:
                            # print(f"ACK {sequence_number} received by {peer_address}")
                            sequence_number += 1
                            break  # Exit the retry loop for this chunk

                    except socket.timeout:
                        count += 1
                        print(f"Timeout occurred for chunk {i + 1}. Retransmitting... (Attempt {count})")
                if count>3: 
                    print("The message was not recieved please send again")

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
