#!/bin/bash
set -x

# Create a test file
echo "Hello, this is a test file" > test.txt

# Run server in background
sudo ./server lo &
SERVER_PID=$!

# Wait for server to start
sleep 1

# Run client commands
sudo ./client lo backup test.txt
sudo ./client lo verifica test.txt
mv test.txt test.txt.orig
sudo ./client lo restaura test.txt

# Compare files
diff test.txt test.txt.orig

# Cleanup
kill $SERVER_PID
rm -f test.txt test.txt.orig