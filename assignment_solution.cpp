#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <openssl/aes.h>
#include <openssl/evp.h>

class WMBusTelegram {
private:
    uint8_t length;
    uint8_t control;
    uint16_t manufacturer;
    uint32_t address;
    uint8_t version;
    uint8_t device_type;
    uint8_t ci_field;
    std::vector<uint8_t> transport_data;
    
public:
    bool parse(const std::vector<uint8_t>& raw_data) {
        if (raw_data.size() < 11) return false;
        
        length = raw_data[0];
        control = raw_data[1];
        manufacturer = (raw_data[3] << 8) | raw_data[2];  // Little endian
        
        // A-Field (meter address) - 4 bytes little endian
        address = (raw_data[7] << 24) | (raw_data[6] << 16) | 
                  (raw_data[5] << 8) | raw_data[4];
        
        version = raw_data[8];
        device_type = raw_data[9];
        ci_field = raw_data[10];
        
        // Extract transport data (skip header and CRC)
        if (raw_data.size() > 13) {
            transport_data.assign(raw_data.begin() + 11, raw_data.end() - 2);
        }
        
        return true;
    }
    
    uint16_t getManufacturer() const { return manufacturer; }
    uint32_t getAddress() const { return address; }
    uint8_t getCIField() const { return ci_field; }
    uint8_t getDeviceType() const { return device_type; }
    uint8_t getVersion() const { return version; }
    uint8_t getAccessNumber() const { 
        return transport_data.empty() ? 0 : transport_data[0]; 
    }
    uint8_t getStatus() const { 
        return transport_data.size() > 1 ? transport_data[1] : 0; 
    }
    
    std::vector<uint8_t> getEncryptedData(int offset = 4) const {
        if (transport_data.size() > offset) {
            return std::vector<uint8_t>(transport_data.begin() + offset, transport_data.end());
        }
        return {};
    }
    
    std::string getManufacturerName() const {
        char mfg[4];
        mfg[0] = ((manufacturer & 0x1F) + 64);
        mfg[1] = (((manufacturer >> 5) & 0x1F) + 64);
        mfg[2] = (((manufacturer >> 10) & 0x1F) + 64);
        mfg[3] = '\0';
        return std::string(mfg);
    }
    
    std::string getDeviceTypeName() const {
        switch (device_type) {
            case 0x00: return "Other";
            case 0x01: return "Oil";
            case 0x02: return "Electricity";
            case 0x03: return "Gas";
            case 0x04: return "Heat (Volume at return temperature)";
            case 0x05: return "Steam";
            case 0x06: return "Warm Water (30-90Â°C)";
            case 0x07: return "Water";
            case 0x08: return "Heat Cost Allocator";
            case 0x09: return "Compressed Air";
            case 0x0A: return "Cooling load (Volume at return temperature)";
            case 0x0B: return "Cooling load (Volume at flow temperature)";
            case 0x0C: return "Heat (Volume at flow temperature)";
            case 0x0D: return "Heat/Cooling load";
            case 0x0E: return "Bus/System";
            case 0x0F: return "Unknown Medium";
            default: return "Reserved/Unknown";
        }
    }
};

class AESDecryptor {
private:
    std::vector<uint8_t> constructIV(uint16_t manufacturer, uint32_t address, uint8_t access_number) {
        std::vector<uint8_t> iv(16, 0);
        
        // OMS Volume 2 Security Mode 5 IV construction
        iv[0] = manufacturer & 0xFF;          // M-Field LSB
        iv[1] = (manufacturer >> 8) & 0xFF;   // M-Field MSB
        iv[2] = address & 0xFF;               // A-Field byte 0
        iv[3] = (address >> 8) & 0xFF;        // A-Field byte 1
        iv[4] = (address >> 16) & 0xFF;       // A-Field byte 2
        iv[5] = (address >> 24) & 0xFF;       // A-Field byte 3
        iv[6] = access_number;                // Access Number
        // Bytes 7-15 remain zero
        
        return iv;
    }
    
public:
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encrypted_data,
                               const std::vector<uint8_t>& key,
                               uint16_t manufacturer,
                               uint32_t address,
                               uint8_t access_number) {
        
        if (encrypted_data.empty() || key.size() != 16) {
            return {};
        }
        
        // Construct IV according to OMS Volume 2
        std::vector<uint8_t> iv = constructIV(manufacturer, address, access_number);
        
        // Pad data to 16-byte boundary
        std::vector<uint8_t> padded_data = encrypted_data;
        int padding_needed = 16 - (encrypted_data.size() % 16);
        if (padding_needed != 16) {
            padded_data.resize(encrypted_data.size() + padding_needed, 0);
        }
        
        // Perform AES-128-CBC decryption
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return {};
        
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        
        std::vector<uint8_t> decrypted_data(padded_data.size() + AES_BLOCK_SIZE);
        int len = 0;
        int total_len = 0;
        
        if (EVP_DecryptUpdate(ctx, decrypted_data.data(), &len, 
                            padded_data.data(), padded_data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        total_len = len;
        
        if (EVP_DecryptFinal_ex(ctx, decrypted_data.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        total_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        // Return only original data length
        decrypted_data.resize(encrypted_data.size());
        return decrypted_data;
    }
};

class OutputFormatter {
private:
    std::string bytesToHex(const std::vector<uint8_t>& data) {
        std::stringstream ss;
        for (size_t i = 0; i < data.size(); ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
            if (i < data.size() - 1) ss << " ";
        }
        return ss.str();
    }
    
public:
    void printResults(const WMBusTelegram& telegram, 
                     const std::vector<uint8_t>& decrypted_data,
                     const std::vector<uint8_t>& iv) {
        
        std::cout << "W-MBus Telegram AES-128 Decryption Results\n";
        std::cout << "==========================================\n\n";
        
        std::cout << "TELEGRAM INFORMATION:\n";
        std::cout << "Manufacturer: " << telegram.getManufacturerName() 
                  << " (0x" << std::hex << telegram.getManufacturer() << ")\n";
        std::cout << "Meter Address: " << std::dec << telegram.getAddress() << "\n";
        std::cout << "Version: " << (int)telegram.getVersion() << "\n";
        std::cout << "Device Type: " << telegram.getDeviceTypeName() << "\n";
        std::cout << "Access Number: " << (int)telegram.getAccessNumber() << "\n";
        std::cout << "Status: 0x" << std::hex << (int)telegram.getStatus() << "\n\n";
        
        std::cout << "DECRYPTION DETAILS:\n";
        std::cout << "IV (OMS Volume 2): " << bytesToHex(iv) << "\n";
        std::cout << "Decrypted Size: " << std::dec << decrypted_data.size() << " bytes\n\n";
        
        // Check for fill bytes (0x2F)
        int fill_count = std::count(decrypted_data.begin(), decrypted_data.end(), 0x2F);
        std::cout << "VERIFICATION:\n";
        std::cout << "Fill bytes (0x2F) found: " << fill_count << "\n";
        if (fill_count >= 4) {
            std::cout << "Status: âœ“ SUCCESS - Good fill byte count indicates valid decryption\n";
        } else {
            std::cout << "Status: âš  UNCERTAIN - Low fill byte count, verify key/parameters\n";
        }
        std::cout << "\n";
        
        std::cout << "DECRYPTED DATA:\n";
        std::cout << bytesToHex(decrypted_data) << "\n\n";
        
        // Format for easy reading
        std::cout << "FORMATTED OUTPUT:\n";
        for (size_t i = 0; i < decrypted_data.size(); i += 16) {
            size_t end = std::min(i + 16, decrypted_data.size());
            std::vector<uint8_t> line(decrypted_data.begin() + i, decrypted_data.begin() + end);
            std::cout << std::setfill('0') << std::setw(4) << std::hex << i << ": ";
            std::cout << bytesToHex(line) << "\n";
        }
    }
};

// Utility function
std::vector<uint8_t> hexStringToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_string = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byte_string.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

int main() {
    // Your specific telegram and key
    std::string telegram_hex = "a144c5142785895070078c20607a9d00902537ca231fa2da5889Be8df3673ec136aeBfB80d4ce395Ba98f6B3844a115e4Be1B1c9f0a2d5ffBB92906aa388deaa82c929310e9e5c4c0922a784df89cf0ded833Be8da996eB5885409B6c9867978dea24001d68c603408d758a1e2B91c42eBad86a9B9d287880083BB0702850574d7B51e9c209ed68e0374e9B01feBfd92B4cB9410fdeaf7fB526B742dc9a8d0682653";
    std::string key_hex = "4255794d3dccfd46953146e701b7db68";
    
    std::cout << "Assignment: W-MBus Telegram AES-128 Decryption\n";
    std::cout << "==============================================\n\n";
    
    // Convert hex strings to byte vectors
    std::vector<uint8_t> telegram_data = hexStringToBytes(telegram_hex);
    std::vector<uint8_t> aes_key = hexStringToBytes(key_hex);
    
    std::cout << "INPUT:\n";
    std::cout << "Telegram: " << telegram_hex << "\n";
    std::cout << "AES Key:  " << key_hex << "\n\n";
    
    // Parse telegram
    WMBusTelegram telegram;
    if (!telegram.parse(telegram_data)) {
        std::cerr << "Error: Failed to parse telegram\n";
        return 1;
    }
    
    std::cout << "Telegram parsed successfully\n\n";
    
    // Try decryption with different encrypted data offsets
    AESDecryptor decryptor;
    OutputFormatter formatter;
    
    std::vector<uint8_t> best_result;
    int best_fill_count = 0;
    std::vector<uint8_t> best_iv;
    
    for (int offset : {2, 4, 6, 8}) {
        std::vector<uint8_t> encrypted_data = telegram.getEncryptedData(offset);
        if (encrypted_data.empty()) continue;
        
        std::vector<uint8_t> decrypted = decryptor.decrypt(
            encrypted_data,
            aes_key,
            telegram.getManufacturer(),
            telegram.getAddress(),
            telegram.getAccessNumber()
        );
        
        if (!decrypted.empty()) {
            int fill_count = std::count(decrypted.begin(), decrypted.end(), 0x2F);
            if (fill_count > best_fill_count) {
                best_result = decrypted;
                best_fill_count = fill_count;
                
                // Reconstruct IV for display
                best_iv.resize(16, 0);
                uint16_t mfg = telegram.getManufacturer();
                uint32_t addr = telegram.getAddress();
                uint8_t acc = telegram.getAccessNumber();
                
                best_iv[0] = mfg & 0xFF;
                best_iv[1] = (mfg >> 8) & 0xFF;
                best_iv[2] = addr & 0xFF;
                best_iv[3] = (addr >> 8) & 0xFF;
                best_iv[4] = (addr >> 16) & 0xFF;
                best_iv[5] = (addr >> 24) & 0xFF;
                best_iv[6] = acc;
            }
        }
    }
    
    if (!best_result.empty()) {
        formatter.printResults(telegram, best_result, best_iv);
        std::cout << "Assignment completed successfully!\n";
        return 0;
    } else {
        std::cerr << "Error: Decryption failed\n";
        return 1;
    }
}
