# Create a virtual interface for testing
sudo ip link add veth0 type veth peer name veth1

# Bring up both interfaces
sudo ip link set veth0 up
sudo ip link set veth1 up

# Run server on one virtual interface
sudo ./server veth0

# Run client on the other virtual interface
sudo ./client veth1 backup file.txt