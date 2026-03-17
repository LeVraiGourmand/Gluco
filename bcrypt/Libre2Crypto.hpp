#ifndef LIBRE2_CRYPTO_HPP
#define LIBRE2_CRYPTO_HPP

#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>

// Inclusion des librairies C de base (TinyCrypt)
extern "C" {
    #include "tinycrypt/ccm_mode.h"
    #include "tinycrypt/aes.h"
}

class Libre2Crypto {
private:
    static constexpr const int noncelen = 13;
    static constexpr const int taglen = 4;
    static constexpr const int iv_enc_len = 8;

    // Tableaux de descripteurs de paquets selon le type de communication (kind)
    static constexpr const uint8_t packetDescriptor[][3] = {
        {0x00, 0x00, 0x00},
        {0x00, 0x00, 0x0F},
        {0x00, 0x00, 0xF0},
        {0x00, 0x0F, 0x00},
        {0x00, 0xF0, 0x00},
        {0x0F, 0x00, 0x00},
        {0xF0, 0x00, 0x00},
        {0x44, 0x00, 0x00}
    };

    int outCryptoSequence;
    uint8_t iv_enc[iv_enc_len];
    uint8_t key[16];

    // Fonction interne de chiffrement basée sur TinyCrypt CCM
    bool selfencrypt(const uint8_t* input, int inputlen, uint8_t* encrypted, uint8_t* nonce) {
        struct tc_ccm_mode_struct c;
        struct tc_aes_key_sched_struct sched;
        
        tc_aes128_set_encrypt_key(&sched, key);
        int result = tc_ccm_config(&c, &sched, nonce, noncelen, taglen);
        
        if (result == 0) {
            std::cerr << "Libre2Crypto: tc_ccm_config failed" << std::endl;
            return false;
        }
        
        int encrlen = inputlen + taglen;
        result = tc_ccm_generation_encryption(encrypted, encrlen, nullptr, 0, input, inputlen, &c);
        
        if (result == 0) {
            std::cerr << "Libre2Crypto: tc_ccm_generation_encryption failed" << std::endl;
            return false;
        }
        return true;
    }

    // Fonction interne de déchiffrement basée sur TinyCrypt CCM
    bool selfdecrypt(const uint8_t* encrypted, int encryplen, uint8_t* plain, uint8_t* nonce) {
        struct tc_ccm_mode_struct c;
        struct tc_aes_key_sched_struct sched;
        
        tc_aes128_set_encrypt_key(&sched, key);
        int result = tc_ccm_config(&c, &sched, nonce, noncelen, taglen);
        
        if (result == 0) {
            std::cerr << "Libre2Crypto: tc_ccm_config failed" << std::endl;
            return false;
        }
        
        const int decryptlen = encryplen - taglen;
        result = tc_ccm_decryption_verification(plain, decryptlen, nullptr, 0, encrypted, encryplen, &c);
        
        if (result == 0) {
            std::cerr << "Libre2Crypto: tc_ccm_decryption_verification failed" << std::endl;
            return false;
        }
        return true;    
    }

public:
    /**
     * Constructeur: Initialise la classe avec la clé (16 octets) et l'IV (8 octets) 
     * récupérés lors de la phase NFC ou générés à partir de l'UID.
     */
    Libre2Crypto(const std::vector<uint8_t>& encryption_key, const std::vector<uint8_t>& initialization_vector) {
        if (encryption_key.size() != 16 || initialization_vector.size() != 8) {
            throw std::invalid_argument("Taille de clé (16) ou IV (8) invalide.");
        }
        
        std::memcpy(this->key, encryption_key.data(), 16);
        std::memcpy(this->iv_enc, initialization_vector.data(), 8);
        this->outCryptoSequence = 1; // Séquence toujours initialisée à 1 au démarrage
    }

    /**
     * Déchiffre un paquet reçu du Libre 2.
     * @param kind Le type de paquet (souvent 1 pour le streaming BLE)
     * @param encrypted_data Le vecteur contenant les données chiffrées reçues via SimpleBLE
     * @param decrypted_data Le vecteur de sortie qui contiendra les données en clair (brutes)
     * @return true si le déchiffrement (et la vérification du MAC) a réussi
     */
    bool decrypt_packet(int kind, const std::vector<uint8_t>& encrypted_data, std::vector<uint8_t>& decrypted_data) {
        if (encrypted_data.size() < 7) {
            return false; // Paquet trop petit pour contenir un MAC et un compteur
        }

        int inputlen = encrypted_data.size();
        int encryptlen = inputlen - 2; // Les 2 derniers octets sont le compteur de séquence
        int plainlen = encryptlen - taglen; // Le payload réel (sans le MAC de 4 octets)
        
        decrypted_data.resize(plainlen);
        
        // Construction du Nonce (13 octets)
        uint8_t nonce[13];
        std::memcpy(nonce + 5, iv_enc, 8); // Les 8 derniers octets viennent de l'IV
        std::memcpy(nonce, encrypted_data.data() + encryptlen, 2); // Les 2 premiers viennent de la séquence du paquet
        std::memcpy(nonce + 2, packetDescriptor[kind], 3); // 3 octets pour le "kind"
        
        return selfdecrypt(encrypted_data.data(), encryptlen, decrypted_data.data(), nonce);
    }

    /**
     * Chiffre un paquet à envoyer au Libre 2 (ex: Commandes spécifiques).
     * @param kind Le type de paquet (souvent 1)
     * @param plain_data Les données en clair à envoyer
     * @param encrypted_data Le vecteur de sortie contenant le paquet prêt à être écrit via SimpleBLE
     * @return true si le chiffrement a réussi
     */
    bool encrypt_packet(int kind, const std::vector<uint8_t>& plain_data, std::vector<uint8_t>& encrypted_data) {
        if (plain_data.empty()) return false;

        int inlen = plain_data.size();
        int encryptlen = inlen + taglen; // Taille après chiffrement (données + MAC de 4 octets)
        int outlen = encryptlen + 2;     // Taille totale (données chiffrées + MAC + séquence de 2 octets)
        
        encrypted_data.resize(outlen);

        // Construction du Nonce (13 octets)
        uint8_t nonce[13];
        std::memcpy(nonce + 5, iv_enc, 8); // Les 8 derniers octets viennent de l'IV
        nonce[0] = (uint8_t)(outCryptoSequence & 0xFF);         // Séquence sortante (LSB)
        nonce[1] = (uint8_t)((outCryptoSequence >> 8) & 0xFF);  // Séquence sortante (MSB)
        std::memcpy(nonce + 2, packetDescriptor[kind], 3);      // 3 octets pour le "kind"

        bool success = selfencrypt(plain_data.data(), inlen, encrypted_data.data(), nonce);

        if (success) {
            // Ajout du compteur de séquence à la fin du paquet chiffré
            encrypted_data[encryptlen] = nonce[0];
            encrypted_data[encryptlen + 1] = nonce[1];
            outCryptoSequence++; // Incrémentation pour le prochain paquet
        }

        return success;
    }
};

#endif // LIBRE2_CRYPTO_HPP