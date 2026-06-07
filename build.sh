#!/bin/bash
# build.sh - QMSP Full Build and Run Script

set -e

if [ -d "CS544-Project-QMSP" ]; then
    echo "[*] Directory already exists, skipping clone..."
    cd CS544-Project-QMSP
else
    echo "[*] Cloning repository..."
    git clone https://github.com/AnuragRSimha/CS544-Project-QMSP.git
    cd CS544-Project-QMSP
fi

echo "[*] Generating TLS certificate..."
python3 certgen.py

PROJECT_DIR="$(pwd)"
CLIENT_CMD_1="cd '$PROJECT_DIR' && sleep 6 && python3 qmsp_client.py --host 127.0.0.1 --user admin --password adminpass --insecure --keepalive 30; exec bash"
CLIENT_CMD_2="cd '$PROJECT_DIR' && sleep 6 && python3 qmsp_client.py --host 127.0.0.1 --user admin --password adminpass --insecure --keepalive 30; exec bash"

echo "[*] Opening Wireshark..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    open -a Wireshark 2>/dev/null || echo "[!] Wireshark not found. Install it from https://www.wireshark.org/download.html"
elif command -v wireshark &> /dev/null; then
    wireshark &
else
    echo "[!] Wireshark not found. Install it with: sudo apt-get install -y wireshark"
fi

echo "[*] Opening two client terminals (will connect in 3-4 seconds)..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    osascript -e "tell application \"Terminal\" to do script \"$CLIENT_CMD_1\""
    osascript -e "tell application \"Terminal\" to do script \"$CLIENT_CMD_2\""
elif command -v gnome-terminal &> /dev/null; then
    gnome-terminal -- bash -c "$CLIENT_CMD_1"
    gnome-terminal -- bash -c "$CLIENT_CMD_2"
elif command -v konsole &> /dev/null; then
    konsole -e bash -c "$CLIENT_CMD_1" &
    konsole -e bash -c "$CLIENT_CMD_2" &
elif command -v xfce4-terminal &> /dev/null; then
    xfce4-terminal -e "bash -c \"$CLIENT_CMD_1\"" &
    xfce4-terminal -e "bash -c \"$CLIENT_CMD_2\"" &
elif command -v xterm &> /dev/null; then
    xterm -e "bash -c \"$CLIENT_CMD_1\"" &
    xterm -e "bash -c \"$CLIENT_CMD_2\"" &
elif command -v tmux &> /dev/null; then
    echo "[*] No GUI terminal found, using tmux..."
    tmux new-window -d "bash -c \"$CLIENT_CMD_1\""
    tmux new-window -d "bash -c \"$CLIENT_CMD_2\""
    echo "[*] Two clients running in new tmux windows (switch with Ctrl+B then N)."
else
    echo "[*] No terminal emulator found, installing xterm..."
    sudo apt-get install -y xterm
    xterm -e "bash -c \"$CLIENT_CMD_1\"" &
    xterm -e "bash -c \"$CLIENT_CMD_2\"" &
fi

echo "[*] Starting QMSP server (Ctrl+C to stop)..."
python3 qmsp_server.py