#!/bin/bash

echo "Wait for installing script....."
sudo pip3 install -r requirements.txt
sudo chmod +x sunifa.py 
sudo cp sunifa.py /usr/bin/sunifa
echo ""
echo ""
echo "You can run the script"
echo "sunifa [Interface name] [w or r] [PcapFileName]"
