# Makefile for compiling C++ installation programs

CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra

# Default target
all: install_wazuh install_security_tools

# Compile Wazuh Manager installer
install_wazuh: install_wazuh.cpp
	$(CXX) $(CXXFLAGS) install_wazuh.cpp -o install_wazuh

# Compile Security Tools installer
install_security_tools: install_security_tools.cpp
	$(CXX) $(CXXFLAGS) install_security_tools.cpp -o install_security_tools

# Clean up compiled executables
clean:
	rm -f install_wazuh install_security_tools *.exe

# Phony targets
.PHONY: all clean