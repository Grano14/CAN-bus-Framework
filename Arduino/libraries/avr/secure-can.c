#pragma GCC optimize ("O3")
#pragma GCC optimize ("unroll-loops")

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "ascon-avr.h"

// Funzione per invio del frame di Auth
//      data input: 
//          data_in[8]          => vettore di 8 byte che contiene i dati generati dalla ECU
//          auth[8]             => vettore di 8 byte per i dati del frame di autenticazione (prev_nonce + tag)
//          encrypted_data[8]   => vettore di 8 byte per i dati in forma cifrata dainviare nel frame dati (con ID + 1)
void send_auth_frame(uint8_t data_in[8], uint8_t auth[8], uint8_t encrypted_data[8], uint8_t prev_nonce[4], uint8_t next_nonce[4]) {

    // Definizione chiave di test
    static const unsigned char static_key[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        };

    // Definizione delle variabili di utility per la funzione
    static unsigned char extended_nonce[16] = {0};
    // Definizione della variabile ciphertext_and_tag per contenere il cifrato + il tag
    static uint8_t ciphertext_and_tag[12]; 

    // Genera il next_nonce usato per cifrate i dati attuali 
    #pragma GCC unroll 4
    for(uint8_t i = 0; i < 4; i++){
        next_nonce[i] = (uint8_t)rand();
    } 

    // Estensione del next_nonce a 16 byte (gli ultimi 12 byte sono tutti pari a 0)
    memcpy(extended_nonce, next_nonce, 4);
    
    // Definiizone della variabile clen che contiene il valore della lunghezza del testo cifrato generato
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

    // Scambio nonce (quello attuale diventa il precedente nel prossimo round
    #pragma GCC unroll 4
    for(uint8_t i = 0; i < 4; i++){
        prev_nonce[i] = next_nonce[i];
    }

}

// Funzione di ricezione dei dati di autenticazione per decifrare e validare i dati cifrati già ricevuti
//      dati input:
//          msg_in[8]       => vettore di 8 byte che contiene i dati di autenticazione per validare i dati cifrati e il tag dei futiri dati cifrati
int receive_auth_frame(const uint8_t msg_in[8], uint8_t last_encripted_data[8], uint8_t last_tag[4], uint8_t *auth_out) {

    // Salvataggio del nonce (primi 4 byte di msg_in) per validare i dati cifrati attualmente salvati in last_encripted_data
    uint8_t nonce[4] = {0, 0, 0, 0};
    #pragma GCC unroll 4
    for(int i = 0; i < 4; i++){
        nonce[i] = msg_in[i];
    }

    // Ricostruzione dela struttura ASCON per la decifratura: 8 byte di testo cifrato (da ID 501) + 16 byte di Tag
    unsigned char ciphertext_and_tag[8 + 4] = {0};
    // Copia del testo cifrato (già salvato quando si sono ricevuti i dati)
    memcpy(ciphertext_and_tag, last_encripted_data, 8);    
    // Copia del tag dopo i dati cifrati (il tag è cpntenuto nella variabile last_tag impostata quando si è ricevuto l'auth frame precedente)
    memcpy(ciphertext_and_tag + 8, last_tag, 4);          

    // Creazione variabile per i dati decifrati e la loro dimensione
    unsigned char decrypted_data[8];
    unsigned long long mlen;

    // Estensione del nonce a 16 byte
    unsigned char extended_nonce[16] = {0};
    memcpy(extended_nonce, nonce, 4);

    // Definizione chiave di test
    static const unsigned char static_key[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        };

    // Chiamata alla tua funzione originale ASCON (da decrypt.c) per decifratura e validazione
    int decryption_status = crypto_aead_decrypt(
        decrypted_data, &mlen, NULL, ciphertext_and_tag, 8 + 4, NULL, 0, extended_nonce, static_key
    );

    // Verifica stato della decifratura
    if (decryption_status == 0) {
        // Tag verificato con successo, salvataggio dati in chiaro in auth_out
        #pragma GCC unroll 4
        for(int i = 0; i < 8; i++) auth_out[i] = decrypted_data[i];

    }
    // Salvataggio del tag attuale (appena ricevuto negli ultimi 4 byte dei dati) utile per i futiri dati che vengono inviati
    #pragma GCC unroll 4
    for(int i = 0; i < 4; i++){
        last_tag[i] = msg_in[i + 4];
    }

    return decryption_status;

}