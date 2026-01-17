# Wazuh Manager Installation Automation

This repository contains C++ programs for automating the installation of security tools on Ubuntu servers.

## Programs

### 1. Wazuh Manager Installer (`install_wazuh.cpp`)

Automates the installation of Wazuh Manager on an Ubuntu server. It starts by updating and upgrading the system, then proceeds with adding the Wazuh repository, installing dependencies, and setting up the Wazuh Manager service.

### 2. Security Tools Installer (`install_security_tools.cpp`)

Automates the installation of multiple security tools on Ubuntu servers: Suricata, Falco, ClamAV, and Wazuh Agent. Starts with system update and upgrade.

## Prerequisites

- Ubuntu server (e.g., AWS EC2 instance)
- Root or sudo privileges
- Internet connection for downloading packages
- C++ compiler (g++) installed on the server

## Installation and Usage

### Using Makefile (Recommended)
1. Ensure `make` is installed on your system.
2. Run `make` to compile all programs:
   ```
   make
   ```
3. Or compile specific programs:
   ```
   make install_wazuh
   make install_security_tools
   ```
4. Run the programs with sudo privileges:
   ```
   sudo ./install_wazuh
   sudo ./install_security_tools
   ```
5. To clean up compiled files:
   ```
   make clean
   ```

### Manual Compilation
1. Transfer the desired `.cpp` file to your Ubuntu server.
2. If not already installed, install g++:
   ```
   sudo apt update
   sudo apt install -y g++
   ```
3. Compile the program:
   ```
   g++ <filename>.cpp -o <executable_name>
   ```
4. Run the program with sudo privileges:
   ```
   sudo ./<executable_name>
   ```

### For Wazuh Manager Installer:
- File: `install_wazuh.cpp`
- Executable: `install_wazuh`

### For Security Tools Installer:
- File: `install_security_tools.cpp`
- Executable: `install_security_tools`

## Installed Tools

### Security Tools Installer installs:
- **Suricata**: Network IDS/IPS
- **Falco**: Runtime security monitoring
- **ClamAV**: Antivirus engine
- **Wazuh Agent**: Security monitoring agent (requires configuration to connect to Wazuh Manager)

## Notes

- Ensure your system meets the hardware and software requirements for the installed tools.
- Wazuh Agent installation requires additional configuration to connect to a Wazuh Manager.
- The programs use the latest stable versions available in the repositories.
- All installations are performed with non-interactive flags where possible.

## License

This project is provided as-is for educational and automation purposes. Refer to the respective tool's licensing for the installed software.