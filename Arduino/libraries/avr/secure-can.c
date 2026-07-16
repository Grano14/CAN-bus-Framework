#pragma GCC optimize ("O3")
#pragma GCC optimize ("unroll-loops")

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "ascon-avr.h"

// Funzione per invio del frame di Auth
void send_auth_frame(uint8_t data_in[8], uint8_t auth[8], uint8_t encrypted_data[8], uint8_t prev_nonce[4], uint8_t next_nonce[4], uint8_t sync_nonce[4]) {

    // Definizione chiave di test
    static const unsigned char static_key[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        };

    // Definizione delle variabili di utility per la funzione
    static unsigned char extended_nonce[16] = {0};
    // Definizione della variabile ciphertext_and_tag per contenere il cifrato + il tag
    static uint8_t ciphertext_and_tag[12]; 

    // Incremento il contatore di 1
    uint32_t contatore = ((uint32_t)prev_nonce[0] << 24) | 
                         ((uint32_t)prev_nonce[1] << 16) | 
                         ((uint32_t)prev_nonce[2] << 8)  | 
                          (uint32_t)prev_nonce[3];

    contatore++;

    next_nonce[0] = (contatore >> 24) & 0xFF;
    next_nonce[1] = (contatore >> 16) & 0xFF;
    next_nonce[2] = (contatore >> 8)  & 0xFF;
    next_nonce[3] = contatore & 0xFF;
    

    // NUOVA STRUTTURA EXTENDED NONCE (CIFRATURA):
    memcpy(extended_nonce, sync_nonce, 4);
    memcpy(extended_nonce + 4, next_nonce, 4);
    
    // Definizione della variabile clen che contiene il valore della lunghezza del testo cifrato generato
    unsigned long long clen;

    // Esecuzione della cifratura autenticata ASCON
    crypto_aead_encrypt(ciphertext_and_tag, &clen, data_in, 8, NULL, 0, NULL, extended_nonce, static_key);

    // Memorizzazione del ciphertext (primi 8 byte dell'output di Ascon) per il frame dati
    memcpy(encrypted_data, ciphertext_and_tag, 8);

    // Scrittura dei dati di auth (i primi 4 byte sono il vecchio nonce i successivi 4 byte sono il tag)
    #pragma GCC unroll 4
    for(uint8_t i = 0; i < 4; i++) auth[i] = prev_nonce[i];
    #pragma GCC unroll 4
    for(uint8_t i = 4; i < 8; i++) auth[i] = ciphertext_and_tag[8 + (i - 4)];

    // Scambio nonce (quello attuale diventa il precedente nel prossimo round)
    #pragma GCC unroll 4
    for(uint8_t i = 0; i < 4; i++){
        prev_nonce[i] = next_nonce[i];
    }

}

// Funzione di ricezione dei dati di autenticazione per decifrare e validare i dati cifrati già ricevuti
int receive_auth_frame(const uint8_t msg_in[8], uint8_t last_encripted_data[8], uint8_t last_tag[4], uint8_t *auth_out, uint8_t sync_nonce[4]) {

    static uint8_t counter_rx[4] = {0, 0, 0, 0};

    // Salvataggio del nonce (primi 4 byte di msg_in) per validare i dati cifrati attualmente salvati in last_encripted_data
    uint8_t counter_tx[4] = {0, 0, 0, 0};
    #pragma GCC unroll 4
    for(int i = 0; i < 4; i++){
        counter_tx[i] = msg_in[i];
    }

    uint32_t val_tx = ((uint32_t)counter_tx[0] << 24) | 
                      ((uint32_t)counter_tx[1] << 16) | 
                      ((uint32_t)counter_tx[2] << 8)  | 
                       (uint32_t)counter_tx[3];

    uint32_t val_rx = ((uint32_t)counter_rx[0] << 24) | 
                      ((uint32_t)counter_rx[1] << 16) | 
                      ((uint32_t)counter_rx[2] << 8)  | 
                       (uint32_t)counter_rx[3];

    // Ricostruzione della struttura ASCON per la decifratura: 8 byte di testo cifrato + 4 byte di Tag
    unsigned char ciphertext_and_tag[8 + 4] = {0};
    // Copia del testo cifrato (già salvato quando si sono ricevuti i dati)
    memcpy(ciphertext_and_tag, last_encripted_data, 8);    
    // Copia del tag dopo i dati cifrati
    memcpy(ciphertext_and_tag + 8, last_tag, 4);          

    // Creazione variabile per i dati decifrati e la loro dimensione
    unsigned char decrypted_data[8];
    unsigned long long mlen;

    // NUOVA STRUTTURA EXTENDED NONCE (DECIFRATURA):
    // Inizializzazione pulita a zero per azzerare i vecchi stati della memoria
    unsigned char extended_nonce[16] = {0};
    memcpy(extended_nonce, sync_nonce, 4);
    memcpy(extended_nonce + 4, counter_tx, 4);

    // Definizione chiave di test
    static const unsigned char static_key[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        };

    // Chiamata alla tua funzione originale ASCON per decifratura e validazione
    int decryption_status = crypto_aead_decrypt(
        decrypted_data, &mlen, NULL, ciphertext_and_tag, 8 + 4, NULL, 0, extended_nonce, static_key
    );

    // Verifica stato della decifratura
    if (decryption_status == 0) {
        if (val_tx > val_rx) {
            // Il messaggio è valido e non è un attacco di Replay
            
            // Aggiorniamo il contatore locale RX con il nuovo valore valido
            counter_rx[0] = counter_tx[0];
            counter_rx[1] = counter_tx[1];
            counter_rx[2] = counter_tx[2];
            counter_rx[3] = counter_tx[3];
            
        }
        else{
            decryption_status = 1;
        }

        // Tag verificato con successo, salvataggio dati in chiaro in auth_out
        #pragma GCC unroll 8
        for(int i = 0; i < 8; i++) auth_out[i] = decrypted_data[i];
    }
    
    // Salvataggio del tag attuale (appena ricevuto negli ultimi 4 byte dei dati) utile per i futuri dati che vengono inviati
    #pragma GCC unroll 4
    for(int i = 0; i < 4; i++){
        last_tag[i] = msg_in[i + 4];
    }

    return decryption_status;
}
