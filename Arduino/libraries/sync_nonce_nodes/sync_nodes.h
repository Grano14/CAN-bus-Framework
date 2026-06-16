#ifndef SYNC_NODES_H
#define SYNC_NODES_H

#include <Arduino.h>
#include <Crypto.h>
#include <SHA256.h>

class sync_nodes {
  public:
    // Il costruttore ora richiede solo la chiave segreta (16 byte)
    sync_nodes(const uint8_t* chiaveSegreta);

    // Funzione di inizializzazione (solo variabili interne)
    void begin();

    // Nuove funzioni: analizzano il frame che gli passi tu dal file principale
    void updateTX(uint32_t rxId, uint8_t len, uint8_t* rxBuf, Stream* serialClient = NULL);
    void updateRX(uint32_t rxId, uint8_t len, uint8_t* rxBuf, Stream* serialClient = NULL);

    // Funzioni per gestire i tentativi temporizzati quando non arrivano messaggi
    void gestisciTimeoutTX(void* canInstance, Stream* serialClient = NULL);
    void gestisciTimeoutRX(void* canInstance, Stream* serialClient = NULL);

    // Utility pubbliche
    bool isSynced();
    int32_t getNonce();

  private:
    const uint8_t* _chiave;
    int32_t _nonce;
    volatile bool _synced;
    unsigned long _ultimoTentativoSincro;
    unsigned long _ultimoStampaDiag;

    // ID dedicati alla sincronizzazione (lasciano liberi gli ID del tuo framework)
    const uint16_t CAN_ID_REQ_NONCE  = 0x110;
    const uint16_t CAN_ID_RESP_NONCE = 0x111;
    const uint16_t CAN_ID_SEND_HASH  = 0x112;
    const uint16_t CAN_ID_WAKEUP     = 0x113;

    void chiediNonce(void* canInstance, Stream* serialClient);
    void inviaRispostaHash(void* canInstance, uint8_t* hashBuffer);
    void inviaRichiestaInizializzazione(void* canInstance);
    void calcolaHash(uint32_t nonce, uint8_t* output8Byte);
};

#endif