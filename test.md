# no mint live usb no NixOS usa o shell.
apt install build-essential

# Para rodar no mesmo PC

## Create a virtual interface for testing
sudo ip link add veth0 type veth peer name veth1

## Bring up both interfaces
sudo ip link set veth0 up
sudo ip link set veth1 up

## Run server on one virtual interface
sudo ./server veth0

## Run client on the other virtual interface
sudo ./client veth1 backup file.txt

---
# Rodando em 2 pcs.

## Na maquina A
sudo ip addr add 192.168.1.1/24 dev eno1
sudo ip link set eno1 up

## Na maquina B
sudo ip addr add 192.168.1.2/24 dev eno1
sudo ip link set eno1 up

## Run server on one 
sudo ./server eno1

## Run client on the other
sudo ./client eno backup file.txt
