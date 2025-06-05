#!/bin/bash

# Test script for 3-node token ring
# Ring topology: Alice (6001) -> Bob (6002) -> Charlie (6003) -> Alice

echo "Starting 3-node token ring test..."
echo "Ring topology: Alice (6001) -> Bob (6002) -> Charlie (6003) -> Alice"
echo ""

# Start nodes in separate terminals (this script is for demonstration)
echo "To test the ring network, run these commands in separate terminals:"
echo ""
echo "Terminal 1 (Alice - Token Generator):"
echo "uv run python ring_node.py --config config_A.txt --port 6001"
echo ""
echo "Terminal 2 (Bob):"  
echo "uv run python ring_node.py --config config_B.txt --port 6002"
echo ""
echo "Terminal 3 (Charlie):"
echo "uv run python ring_node.py --config config_C.txt --port 6003"
echo ""
echo "Test commands to try:"
echo "1. send Bob Hello from Alice"
echo "2. send Charlie Hi there"
echo "3. send Alice Testing self-message"
echo "4. send TODOS Broadcast message"
echo "5. faultmode on (then send a message to test error handling)"
echo "6. status (to see node status)"
echo "7. queue (to see message queue)"
echo "8. token (to check token status)"
echo ""
echo "The ring will show:"
echo "- Token passing between nodes"
echo "- Message forwarding through intermediate nodes"
echo "- ACK/NACK responses"
echo "- Error injection and retransmission"
echo "- Broadcast message handling" 