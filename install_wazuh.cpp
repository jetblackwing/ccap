#include &lt;iostream&gt;
#include &lt;cstdlib&gt;
#include &lt;string&gt;

int main() {
    std::cout &lt;&lt; "Starting Wazuh Manager Installation Automation..." &lt;&lt; std::endl;

    // Update package list
    std::cout &lt;&lt; "Updating package list..." &lt;&lt; std::endl;
    int result = system("sudo apt update");
    if (result != 0) {
        std::cerr &lt;&lt; "Failed to update package list." &lt;&lt; std::endl;
        return 1;
    }

    // Upgrade the system
    std::cout &lt;&lt; "Upgrading the system..." &lt;&lt; std::endl;
    result = system("sudo apt upgrade -y");
    if (result != 0) {
        std::cerr &lt;&lt; "Failed to upgrade the system." &lt;&lt; std::endl;
        return 1;
    }

    // Install dependencies
    std::cout &lt;&lt; "Installing dependencies..." &lt;&lt; std::endl;
    result = system("sudo apt-get install -y curl gnupg apt-transport-https");
    if (result != 0) {
        std::cerr &lt;&lt; "Failed to install dependencies." &lt;&lt; std::endl;
        return 1;
    }

    // Add Wazuh GPG key
    std::cout &lt;&lt; "Adding Wazuh GPG key..." &lt;&lt; std::endl;
    result = system("curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg");
    if (result != 0) {
        std::cerr &lt;&lt; "Failed to add Wazuh GPG key." &lt;&lt; std::endl;
        return 1;
    }

    // Add Wazuh repository
    std::cout &lt;&lt; "Adding Wazuh repository..." &lt;&lt; std::endl;
    result = system("echo \"deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\" | sudo tee -a /etc/apt/sources.list.d/wazuh.list");
    if (result != 0) {
        std::cerr &lt;&lt; "Failed to add Wazuh repository." &lt;&lt; std::endl;
        return 1;
    }

    // Update package list again
    std::cout &lt;&lt; "Updating package list after adding repository..." &lt;&lt; std::endl;
    result = system("sudo apt update");
    if (result != 0) {
        std::cerr &lt;&lt; "Failed to update package list after adding repository." &lt;&lt; std::endl;
        return 1;
    }

    // Install Wazuh manager
    std::cout &lt;&lt; "Installing Wazuh Manager..." &lt;&lt; std::endl;
    result = system("sudo apt-get install -y wazuh-manager");
    if (result != 0) {
        std::cerr &lt;&lt; "Failed to install Wazuh Manager." &lt;&lt; std::endl;
        return 1;
    }

    // Enable Wazuh manager service
    std::cout &lt;&lt; "Enabling Wazuh Manager service..." &lt;&lt; std::endl;
    result = system("sudo systemctl enable wazuh-manager");
    if (result != 0) {
        std::cerr &lt;&lt; "Failed to enable Wazuh Manager service." &lt;&lt; std::endl;
        return 1;
    }

    // Start Wazuh manager service
    std::cout &lt;&lt; "Starting Wazuh Manager service..." &lt;&lt; std::endl;
    result = system("sudo systemctl start wazuh-manager");
    if (result != 0) {
        std::cerr &lt;&lt; "Failed to start Wazuh Manager service." &lt;&lt; std::endl;
        return 1;
    }

    std::cout &lt;&lt; "Wazuh Manager installation completed successfully!" &lt;&lt; std::endl;
    return 0;
}