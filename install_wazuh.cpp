#include <iostream>
#include <cstdlib>
#include <string>

int main() {
    std::cout << "Starting Wazuh Manager Installation Automation..." << std::endl;

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

    // Install dependencies
    std::cout << "Installing dependencies..." << std::endl;
    result = system("sudo apt-get install -y curl gnupg apt-transport-https");
    if (result != 0) {
        std::cerr << "Failed to install dependencies." << std::endl;
        return 1;
    }

    // Add Wazuh GPG key
    std::cout << "Adding Wazuh GPG key..." << std::endl;
    result = system("curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg");
    if (result != 0) {
        std::cerr << "Failed to add Wazuh GPG key." << std::endl;
        return 1;
    }

    // Add Wazuh repository
    std::cout << "Adding Wazuh repository..." << std::endl;
    result = system("echo \"deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\" | sudo tee -a /etc/apt/sources.list.d/wazuh.list");
    if (result != 0) {
        std::cerr << "Failed to add Wazuh repository." << std::endl;
        return 1;
    }

    // Update package list again
    std::cout << "Updating package list after adding repository..." << std::endl;
    result = system("sudo apt update");
    if (result != 0) {
        std::cerr << "Failed to update package list after adding repository." << std::endl;
        return 1;
    }

    // Install Wazuh manager
    std::cout << "Installing Wazuh Manager..." << std::endl;
    result = system("sudo apt-get install -y wazuh-manager");
    if (result != 0) {
        std::cerr << "Failed to install Wazuh Manager." << std::endl;
        return 1;
    }

    // Enable Wazuh manager service
    std::cout << "Enabling Wazuh Manager service..." << std::endl;
    result = system("sudo systemctl enable wazuh-manager");
    if (result != 0) {
        std::cerr << "Failed to enable Wazuh Manager service." << std::endl;
        return 1;
    }

    // Start Wazuh manager service
    std::cout << "Starting Wazuh Manager service..." << std::endl;
    result = system("sudo systemctl start wazuh-manager");
    if (result != 0) {
        std::cerr << "Failed to start Wazuh Manager service." << std::endl;
        return 1;
    }

    std::cout << "Wazuh Manager installation completed successfully!" << std::endl;
    return 0;
}