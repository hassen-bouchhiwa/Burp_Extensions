#!/bin/bash

# install.sh

set -e

# Update package lists
sudo apt-get update

# Function to install a tool using apt, pip, or git
install_tool() {
    tool_name=$1
    apt_package=$2
    pip_package=$3
    git_repo=$4

    echo "Attempting to install $tool_name using apt..."
    if sudo apt-get install -y $apt_package; then
        echo "$tool_name installed successfully using apt."
        return 0
    fi

    echo "Attempting to install $tool_name using pip..."
    if pip3 install $pip_package; then
        echo "$tool_name installed successfully using pip."
        return 0
    fi

    echo "Attempting to install $tool_name from GitHub..."
    if [ $git_repo ]; then
        git clone $git_repo $tool_name-dev
        sudo ln -s $(pwd)/$tool_name-dev/$tool_name.py /usr/local/bin/$tool_name
        echo "$tool_name installed successfully from GitHub."
        return 0
    fi

    echo "Failed to install $tool_name."
    return 1
}

# Install sqlmap
install_tool "sqlmap" "sqlmap" "sqlmap" "https://github.com/sqlmapproject/sqlmap.git"

# Install dalfox
install_tool "dalfox" "dalfox" "dalfox" "https://github.com/hahwul/dalfox"

# Install tplmap
install_tool "tplmap" "" "" "https://github.com/epinna/tplmap.git"
if [ ! -d "tplmap" ]; then
    git clone https://github.com/epinna/tplmap.git
    cd tplmap
    sudo python3 setup.py install
    cd ..
fi

# Install commix
install_tool "commix" "" "" "https://github.com/commixproject/commix.git"
if [ ! -d "commix-dev" ]; then
    git clone https://github.com/commixproject/commix.git commix-dev
    sudo ln -s $(pwd)/commix-dev/commix.py /usr/local/bin/commix
fi

# Install Python dependencies
pip3 install -r requirements.txt

echo "Installation complete."
