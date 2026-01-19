/*
 * MIT License
 * 
 * Copyright (c) 2026 Arun Vellanikode (arunvellanikode)
 * Copyright (c) 2026 Amal J Krishnan (jetblackwing)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * Project: CCAP (Centralized Cloud Automation Program)
 */



#include <iostream>
#include <cstdlib>
#include <string>
#include <syslog.h>

int main() {
    std::cout << "Starting Security Tools Installation Automation..." << std::endl;

    // Update package list
    std::cout << "Updating package list..." << std::endl;
    int result = system("sudo apt update");
    if (result != 0) {
        std::cerr << "Failed to update package list." << std::endl;
        return 1;
    }

    // Upgrade the system
    std::cout << "Upgrading the system..." << std::endl;
    result = system("sudo apt upgrade -y");
    if (result != 0) {
        std::cerr << "Failed to upgrade the system." << std::endl;
        return 1;
    }

    // Install Suricata
    std::cout << "Installing Suricata..." << std::endl;
    result = system("sudo apt install -y software-properties-common");
    if (result != 0) {
        std::cerr << "Failed to install software-properties-common." << std::endl;
        return 1;
    }
    result = system("sudo add-apt-repository -y ppa:oisf/suricata-stable");
    if (result != 0) {
        std::cerr << "Failed to add Suricata PPA." << std::endl;
        return 1;
    }
    result = system("sudo apt update");
    if (result != 0) {
        std::cerr << "Failed to update after adding PPA." << std::endl;
        return 1;
    }
    result = system("sudo apt install -y suricata");
    if (result != 0) {
        std::cerr << "Failed to install Suricata." << std::endl;
        return 1;
    }
    result = system("sudo systemctl enable suricata");
    if (result != 0) {
        std::cerr << "Failed to enable Suricata service." << std::endl;
        return 1;
    }
    result = system("sudo systemctl start suricata");
    if (result != 0) {
        std::cerr << "Failed to start Suricata service." << std::endl;
        return 1;
    }

    // Install Falco
    std::cout << "Installing Falco..." << std::endl;
    result = system("curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg");
    if (result != 0) {
        std::cerr << "Failed to add Falco GPG key." << std::endl;
        return 1;
    }
    result = system("sudo bash -c 'cat > /etc/apt/sources.list.d/falcosecurity.list << EOF\ndeb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main\nEOF'");
    if (result != 0) {
        std::cerr << "Failed to add Falco repository." << std::endl;
        return 1;
    }
    result = system("sudo apt update");
    if (result != 0) {
        std::cerr << "Failed to update after adding Falco repo." << std::endl;
        return 1;
    }
    result = system("sudo apt install -y falco");
    if (result != 0) {
        std::cerr << "Failed to install Falco." << std::endl;
        return 1;
    }
    result = system("sudo systemctl enable falco");
    if (result != 0) {
        std::cerr << "Failed to enable Falco service." << std::endl;
        return 1;
    }
    result = system("sudo systemctl start falco");
    if (result != 0) {
        std::cerr << "Failed to start Falco service." << std::endl;
        return 1;
    }

    // Install ClamAV
    std::cout << "Installing ClamAV..." << std::endl;
    result = system("sudo apt install -y clamav clamav-daemon");
    if (result != 0) {
        std::cerr << "Failed to install ClamAV." << std::endl;
        return 1;
    }
    result = system("sudo systemctl enable clamav-daemon");
    if (result != 0) {
        std::cerr << "Failed to enable ClamAV daemon." << std::endl;
        return 1;
    }
    result = system("sudo systemctl start clamav-daemon");
    if (result != 0) {
        std::cerr << "Failed to start ClamAV daemon." << std::endl;
        return 1;
    }

    // Install Wazuh Agent
    std::cout << "Installing Wazuh Agent..." << std::endl;
    // Assuming Wazuh repo is not added yet, add it
    result = system("sudo apt-get install -y curl gnupg apt-transport-https");
    if (result != 0) {
        std::cerr << "Failed to install dependencies for Wazuh." << std::endl;
        return 1;
    }
    result = system("curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg");
    if (result != 0) {
        std::cerr << "Failed to add Wazuh GPG key." << std::endl;
        return 1;
    }
    result = system("echo \"deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\" | sudo tee -a /etc/apt/sources.list.d/wazuh.list");
    if (result != 0) {
        std::cerr << "Failed to add Wazuh repository." << std::endl;
        return 1;
    }
    result = system("sudo apt update");
    if (result != 0) {
        std::cerr << "Failed to update after adding Wazuh repo." << std::endl;
        return 1;
    }
    result = system("sudo apt-get install -y wazuh-agent");
    if (result != 0) {
        std::cerr << "Failed to install Wazuh Agent." << std::endl;
        return 1;
    }
    // Note: Wazuh agent needs configuration to connect to manager, but installation is done.

    std::cout << "Security tools installation completed successfully!" << std::endl;
    std::cout << "Note: Wazuh Agent requires configuration to connect to the Wazuh Manager." << std::endl;
    return 0;

    // Adding logging feature.
    // Event logging can be implemented using syslog or a dedicated logging library.
    // Every events and activities which are performed by this script can be logged for auditing and troubleshooting purposes.
    // Log file is created at ./ccap_agent_log.txt
    openlog("CCAP_Agent_Installation", LOG_PID|LOG_CONS, LOG_USER);
    syslog(LOG_INFO, "Security tools installation started.");
    // Log each step of the installation process here...
    syslog(LOG_INFO, "Security tools installation completed successfully.");
    closelog();
}