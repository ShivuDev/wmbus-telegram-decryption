#include <Arduino.h>
#include <WiFi.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include "mbedtls/aes.h"

class ESP32_WMBusDecryptor {
private:
    mbedtls_aes_context aes_ctx;
    
    std::vector<uint8_t> hexStringToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }
    
    std::string bytesToHex(const std::vector<uint8_t>& data) {
        std::string hex;
        char buffer[3];
        for (uint8_t byte : data) {
            sprintf(buffer, "%02X", byte);
            hex += buffer;
        }
        return hex;
    }
    
    std::vector<uint8_t> constructIV(uint16_t manufacturer, uint32_t address, uint8_t access_number) {
        std::vector<uint8_t> iv(16, 0);
        
        // M-Field (2 bytes, little endian)
        iv[0] = manufacturer & 0xFF;
        iv[1] = (manufacturer >> 8) & 0xFF;
        
        // A-Field (4 bytes, little endian)
        iv[2] = address & 0xFF;
        iv[3] = (address >> 8) & 0xFF;
        iv[4] = (address >> 16) & 0xFF;
        iv[5] = (address >> 24) & 0xFF;
        
        // Access Number (1 byte)
        iv[6] = access_number;
        
        return iv;
    }
    
public:
    ESP32_WMBusDecryptor() {
        mbedtls_aes_init(&aes_ctx);
    }
    
    ~ESP32_WMBusDecryptor() {
        mbedtls_aes_free(&aes_ctx);
    }
    
    bool decryptTelegram(const std::string& telegram_hex, const std::string& key_hex) {
        Serial.println("ESP32 W-MBus Telegram Decryptor");
        Serial.println("===============================");
        Serial.println();
        
        // Convert hex strings to byte vectors
        std::vector<uint8_t> telegram_data = hexStringToBytes(telegram_hex);
        std::vector<uint8_t> aes_key = hexStringToBytes(key_hex);
        
        if (aes_key.size() != 16) {
            Serial.println("Error: AES key must be 16 bytes (128 bits)");
            return false;
        }
        
        if (telegram_data.size() < 11) {
            Serial.println("Error: Telegram too short");
            return false;
        }
        
        // Parse telegram header
        uint8_t length = telegram_data[0];
        uint8_t control = telegram_data[1];
        uint16_t manufacturer = (telegram_data[3] << 8) | telegram_data[2];
        uint32_t address = (telegram_data[7] << 24) | (telegram_data[6] << 16) | 
                          (telegram_data[5] << 8) | telegram_data[4];
        uint8_t version = telegram_data[8];
        uint8_t device_type = telegram_data[9];
        uint8_t ci_field = telegram_data[10];
        
        // Extract encrypted payload
        std::vector<uint8_t> encrypted_payload;
        if (telegram_data.size() > 13) {
            encrypted_payload.assign(telegram_data.begin() + 11, telegram_data.end() - 2);
        }
        
        if (encrypted_payload.empty()) {
            Serial.println("Error: No encrypted payload found");
            return false;
        }
        
        // Display telegram info
        Serial.print("Manufacturer: ");
        char mfg[4];
        mfg[0] = ((manufacturer & 0x1F) + 64);
        mfg[1] = (((manufacturer >> 5) & 0x1F) + 64);
        mfg[2] = (((manufacturer >> 10) & 0x1F) + 64);
        mfg[3] = '\0';
        Serial.print(mfg);
        Serial.print(" (0x");
        Serial.print(manufacturer, HEX);
        Serial.println(")");
        
        Serial.print("Meter Address: ");
        Serial.println(address);
        Serial.print("Version: ");
        Serial.println(version);
        Serial.print("Device Type: 0x");
        Serial.println(device_type, HEX);
        Serial.print("CI Field: 0x");
        Serial.println(ci_field, HEX);
        Serial.println();
        
        // Extract access number from encrypted payload
        uint8_t access_number = encrypted_payload[0];
        Serial.print("Access Number: ");
        Serial.println(access_number);
        
        // Construct IV
        std::vector<uint8_t> iv = constructIV(manufacturer, address, access_number);
        
        Serial.print("IV: ");
        Serial.println(bytesToHex(iv).c_str());
        
        // Prepare data for decryption (skip header: access_number, status, config)
        if (encrypted_payload.size() <= 3) {
            Serial.println("Error: Insufficient encrypted data");
            return false;
        }
        
        std::vector<uint8_t> data_to_decrypt(encrypted_payload.begin() + 3, encrypted_payload.end());
        
        // Pad to 16-byte boundary if necessary
        while (data_to_decrypt.size() % 16 != 0) {
            data_to_decrypt.push_back(0x00);
        }
        
        // Set up AES decryption
        if (mbedtls_aes_setkey_dec(&aes_ctx, aes_key.data(), 128) != 0) {
            Serial.println("Error: Failed to set AES key");
            return false;
        }
        
        // Decrypt data block by block
        std::vector<uint8_t> decrypted_data(data_to_decrypt.size());
        std::vector<uint8_t> current_iv = iv; // Working copy of IV
        
        for (size_t i = 0; i < data_to_decrypt.size(); i += 16) {
            if (mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, 16,
                                     current_iv.data(),
                                     data_to_decrypt.data() + i,
                                     decrypted_data.data() + i) != 0) {
                Serial.println("Error: AES decryption failed");
                return false;
            }
        }
        
        // Combine header with decrypted data
        std::vector<uint8_t> full_decrypted;
        full_decrypted.insert(full_decrypted.end(), encrypted_payload.begin(), encrypted_payload.begin() + 3);
        full_decrypted.insert(full_decrypted.end(), decrypted_data.begin(), decrypted_data.end());
        
        // Display results
        Serial.println();
        Serial.println("Decryption Results:");
        Serial.println("==================");
        
        if (full_decrypted.size() >= 3) {
            Serial.print("Status: 0x");
            Serial.println(full_decrypted[1], HEX);
            
            uint16_t config = (full_decrypted[3] << 8) | full_decrypted[2];
            uint8_t security_mode = config & 0x1F;
            uint8_t num_blocks = (config >> 4) & 0x0F;
            
            Serial.print("Configuration: 0x");
            Serial.println(config, HEX);
            Serial.print("Security Mode: ");
            Serial.print(security_mode);
            if (security_mode == 5) {
                Serial.print(" (AES-128-CBC)");
            }
            Serial.println();
            Serial.print("Encrypted Blocks: ");
            Serial.println(num_blocks);
        }
        
        // Check for fill bytes (0x2F) to verify successful decryption
        bool valid_decryption = false;
        if (full_decrypted.size() >= 2) {
            size_t fill_count = 0;
            for (int i = full_decrypted.size() - 1; i >= 0 && full_decrypted[i] == 0x2F; --i) {
                fill_count++;
            }
            valid_decryption = (fill_count >= 2);
        }
        
        Serial.print("Decryption Status: ");
        if (valid_decryption) {
            Serial.println("SUCCESS (Fill bytes 0x2F detected)");
        } else {
            Serial.println("UNCERTAIN (No fill bytes detected)");
        }
        
        Serial.println();
        Serial.print("Raw Decrypted Data: ");
        Serial.println(bytesToHex(full_decrypted).c_str());
        
        return valid_decryption;
    }
};

// Global instance
ESP32_WMBusDecryptor decryptor;

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println();
    Serial.println("ESP32 W-MBus Telegram Decryptor Starting...");
    Serial.println();
    
    // Example encrypted telegram and key
    std::string telegram_hex = "2e4493157856341233037a2a0020055923c95aaa26d1b2e7493b013ec4a6f6d3529b520edff0ea6defc99d6d69ebf3";
    std::string key_hex = "000102030405060708090A0B0C0D0E0F";
    
    Serial.println("Testing with example telegram from OMS specification:");
    Serial.print("Telegram: ");
    Serial.println(telegram_hex.c_str());
    Serial.print("Key: ");
    Serial.println(key_hex.c_str());
    Serial.println();
    
    bool success = decryptor.decryptTelegram(telegram_hex, key_hex);
    
    if (success) {
        Serial.println();
        Serial.println("Decryption completed successfully!");
    } else {
        Serial.println();
        Serial.println("Decryption may have failed. Check key and telegram data.");
    }
}

void loop() {
    // Main loop - could be used for continuous processing
    delay(10000);
    
    // Example: Read telegram from Serial input
    if (Serial.available()) {
        String input = Serial.readStringUntil('\n');
        input.trim();
        
        if (input.startsWith("TELEGRAM:")) {
            String telegram = input.substring(9);
            telegram.trim();
            
            // Wait for key
            Serial.println("Enter AES key (32 hex characters):");
            while (!Serial.available()) {
                delay(100);
            }
            String key = Serial.readStringUntil('\n');
            key.trim();
            
            if (key.length() == 32) {
                Serial.println();
                Serial.println("Processing new telegram...");
                decryptor.decryptTelegram(telegram.c_str(), key.c_str());
            } else {
                Serial.println("Error: Key must be exactly 32 hex characters");
            }
        }
    }
}
