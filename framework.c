#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "Ascon/ascon_functions.h"

#define TX_LOG_FILE "transmission.log"
#define RX_LOG_FILE "reception.log"

// Variabili per gestire i log
static uint32_t tx_counter = 0;
static int initialized = 0;

// Variabili per salvare lo stato degli ultimi dati cifrati
static uint8_t last_encripted_data[8] = {0, 0, 0, 0, 0, 0, 0, 0};
static uint8_t last_tag[4] = {0, 0, 0, 0};

// Funzione per sovrascrivere i file (modalità "w") per svuotarli completamente
void check_and_reset(void) {
    if (!initialized) {
        tx_counter = 0;
        FILE *f1 = fopen(TX_LOG_FILE, "w"); if (f1) fclose(f1);
        FILE *f2 = fopen(RX_LOG_FILE, "w"); if (f2) fclose(f2);
        initialized = 1;
    }
}

// Funzione per invio del frame di Auth
//      data input: 
//          data_in[8]          => vettore di 8 byte che contiene i dati generati dalla ECU
//      data output:
//          auth[8]             => vettore di 8 byte che contiene i dati per il frame di autenticazione (prev_nonce + tag)
//          encrypted_data[8]   => vettore di 8 byte che contiene i dati in forma cifrata dainviare nel frame dati (con ID + 1)
void send_auth_frame(const uint8_t data_in[8], uint8_t auth[8], uint8_t encrypted_data[8]) {

    // Funzione per settare il file di loig
    check_and_reset();

    // Definizione variabili nonce
    static uint8_t prev_nonce[4] = {0, 0, 0, 0};
    static uint8_t next_nonce[4] = {0, 0, 0, 0};
    // Definizione della varuabile che contiene l'output della cifratura con ASCON (8 byte cifrati + 4 byte di tag)
    unsigned char ciphertext_and_tag[8 + 4];
    
    // Generazione dati casuali di invio (sovrascrittura della variabile data_in[8])
    for (int i = 0; i < 8; i++) {
        ((uint8_t*)data_in)[i] = rand() % 256;
    }

    // Definizione chiave di test
    static const unsigned char static_key[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        };

    // Genera il next_nonce usato per cifrate i dati attuali 
    for(int i = 0; i < 4; i++) next_nonce[i] = (uint8_t)(rand() % 256);
    // Estensione del next_nonce a 16 byte (gli ultimi 12 byte sono tutti pari a 0)
    unsigned char extended_nonce[16] = {0};
    memcpy(extended_nonce, next_nonce, 4);
    
    // Definiizone della variabile clen che contiene il valore della lunghezza del testo cifrato generato
    unsigned long long clen;

    // Esecuzione della cifratura autenticata ASCON
    crypto_aead_encrypt(ciphertext_and_tag, &clen, data_in, 8, NULL, 0, NULL, extended_nonce, static_key);

    // Memorizzazione del ciphertext (primi 8 byte dell'output di Ascon) per il frame dati
    memcpy(encrypted_data, ciphertext_and_tag, 8);

    // Scrittura dei dati di auth (i primi 4 byte sono il vecchio nonce i successivi 4 byte sono il tag)
    for(int i = 0; i < 4; i++) auth[i] = prev_nonce[i];
    for(int i = 4; i < 8; i++) auth[i] = ciphertext_and_tag[8 + (i - 4)];

    // Scambio nonce (quello attuale diventa il precedente nel prossimo round
    for(int i = 0; i < 4; i++){
        prev_nonce[i] = next_nonce[i];
    }

    // Codice per i Log
    // Apertura file per scrittura log
    FILE *f = fopen(TX_LOG_FILE, "a");

    if (f != NULL) {
        fprintf(f, "[TX] Generati dati: %02X %02X %02X %02X %02X %02X %02X %02X, il cifrato = %02X %02X %02X %02X %02X %02X %02X %02X e il nonce = %02X %02X %02X %02X e tag= %02X %02X %02X %02X\n",
                data_in[0], data_in[1], data_in[2], data_in[3],
                data_in[4], data_in[5], data_in[6], data_in[7],
                encrypted_data[0], encrypted_data[1], encrypted_data[2], encrypted_data[3],
                encrypted_data[4], encrypted_data[5], encrypted_data[6], encrypted_data[7],
                prev_nonce[0], prev_nonce[1], prev_nonce[2], prev_nonce[3],
                auth[4], auth[5], auth[6], auth[7]);
        fclose(f);
    }

}

// Funzione per l'invio del frame Dati
//      dati input:
//          data_in[8]      => vettore di 8 byte che contiene i dati cifrati da inviare 
//      dati output:
//          data_out[8]     => vettore di 8 byte che contiene i dati cifrati 
//
void send_data_frame(const uint8_t data_in[8], uint8_t data_out[8]){
    // Copia dati in input in output message
    for(int i = 0; i < 8; i++){
        data_out[i] = data_in[i];
    }

    // Apertura file per scrittura log
    FILE *f = fopen(TX_LOG_FILE, "a");

    if (f != NULL) {
        fprintf(f, "[TX] Invio dati: %02X %02X %02X %02X %02X %02X %02X %02X \n",
                data_in[0], data_in[1], data_in[2], data_in[3],
                data_in[4], data_in[5], data_in[6], data_in[7]);
        fclose(f);
    }
}

// Funzione di ricezione dei dati cifrati dal frame data
//      dati input:
//          msg_in[8]       => vettore di 8 byte contenente il testo cifrato ricevuto che viene salvato e controlato successivamente
void receive_data_frame(const uint8_t msg_in[8], uint8_t status) {

    // Salvataggio dei dati cifrati nella variabile last_encripted_data
    for(int i = 0; i < 8; i++){
        last_encripted_data[i] = msg_in[i];
    }

}

// Funzione di ricezione dei dati di autenticazione per decifrare e validare i dati cifrati già ricevuti
//      dati input:
//          msg_in[8]       => vettore di 8 byte che contiene i dati di autenticazione per validare i dati cifrati e il tag dei futiri dati cifrati
void receive_auth_frame(const uint8_t msg_in[8], uint8_t *auth_out, uint8_t status) {

    // Salvataggio del nonce (primi 4 byte di msg_in) per validare i dati cifrati attualmente salvati in last_encripted_data
    uint8_t nonce[4] = {0, 0, 0, 0};
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
        //for(int i = 0; i < 8; i++) auth_out[i] = decrypted_data[i];

        *auth_out = 1;

        // Scrittura log
        FILE *f = fopen(RX_LOG_FILE, "a");

        if (f != NULL) {
            fprintf(f, "[RX] Ricevuto ID 501 fresco -> VALIDAZIONE ASCON OK! Output aggiornato.\n");
            fclose(f);
        }
    } else {
        // Il tag crittografico non corrisponde
       *auth_out = 0;

        // scrittura log
        FILE *f = fopen(RX_LOG_FILE, "a");
        if (f != NULL) {
            fprintf(f, "[RX - ERRORE CRITICO] Tag ASCON fallito! I dati o i parametri non corrispondono.\n");
            fclose(f);
        }
    }

    // scrittura log
    FILE *f = fopen(RX_LOG_FILE, "a");

    if (f != NULL) {
        fprintf(f, "[RX] Dati da decifrare: %02X %02X %02X %02X %02X %02X %02X %02X, il nonce = %02X %02X %02X %02X e il tag = %02X %02X %02X %02X %02X\n",
                last_encripted_data[0], last_encripted_data[1], last_encripted_data[2], last_encripted_data[3],
                last_encripted_data[4], last_encripted_data[5], last_encripted_data[6], last_encripted_data[7],
                nonce[0], nonce[1], nonce[2], nonce[3],
                last_tag[0], last_tag[1], last_tag[2], last_tag[3]);
        fclose(f);
    }

    // Salvataggio del tag attuale (appena ricevuto negli ultimi 4 byte dei dati) utile per i futiri dati che vengono inviati
    for(int i = 0; i < 4; i++){
        last_tag[i] = msg_in[i + 4];
    }

}