#include "sync_nodes.h"
#include <mcp_can.h> 

sync_nodes::sync_nodes(const uint8_t* chiaveSegreta) {
    _chiave = chiaveSegreta;
    _nonce = -1;
    _synced = false;
    _ultimoTentativoSincro = 0;
    _ultimoStampaDiag = 0;
}

void sync_nodes::begin() {
    _synced = false;
    _nonce = -1;
}

bool sync_nodes::isSynced() {
    return _synced;
}

int32_t sync_nodes::getNonce() {
    return _nonce;
}

void sync_nodes::calcolaHash(uint32_t nonce, uint8_t* output8Byte) {
    SHA256 sha256;
    uint8_t hashCompleto[32];
    
    sha256.reset();
    sha256.update(_chiave, 16);
    sha256.update(&nonce, sizeof(nonce));
    sha256.finalize(hashCompleto, 32);
    
    for(int i = 0; i < 8; i++) {
        output8Byte[i] = hashCompleto[i];
    }
}

void sync_nodes::chiediNonce(void* canInstance, Stream* serialClient) {
    MCP_CAN* can = (MCP_CAN*)canInstance;
    unsigned char dummy[1] = {0};
    can->sendMsgBuf(CAN_ID_REQ_NONCE, 0, 0, dummy);
    if(serialClient) serialClient->println(F("[sync_nodes TX] Chiesto Nonce a RX..."));
}

void sync_nodes::inviaRispostaHash(void* canInstance, uint8_t* hashBuffer) {
    MCP_CAN* can = (MCP_CAN*)canInstance;
    can->sendMsgBuf(CAN_ID_SEND_HASH, 0, 8, hashBuffer);
}

void sync_nodes::inviaRichiestaInizializzazione(void* canInstance) {
    MCP_CAN* can = (MCP_CAN*)canInstance;
    unsigned char dummy[1] = {0};
    can->sendMsgBuf(CAN_ID_WAKEUP, 0, 0, dummy);
}

// Analizza passivamente i frame passati dal TX principale
void sync_nodes::updateTX(uint32_t rxId, uint8_t len, uint8_t* rxBuf, Stream* serialClient) {
    if (rxId == CAN_ID_WAKEUP) {
        _synced = false;
    }
    else if (rxId == CAN_ID_RESP_NONCE && len >= 4) {
        _nonce = ((int32_t)rxBuf[0] << 24) | ((int32_t)rxBuf[1] << 16) | ((int32_t)rxBuf[2] << 8) | rxBuf[3];
        _synced = true; 
    }
}

void sync_nodes::gestisciTimeoutTX(void* canInstance, Stream* serialClient) {
    if (!_synced && (millis() - _ultimoTentativoSincro >= 500)) {
        _ultimoTentativoSincro = millis();
        chiediNonce(canInstance, serialClient);
    }

    if (_synced && (millis() - _ultimoStampaDiag >= 4000)) {
        _ultimoStampaDiag = millis();
        if(serialClient) {
            serialClient->print(F("[LIBRERIA TX] Nodi Sincronizzati. Nonce: "));
            serialClient->println(_nonce);
        }
    }
}

// Analizza passivamente i frame passati dal RX principale
void sync_nodes::updateRX(uint32_t rxId, uint8_t len, uint8_t* rxBuf, Stream* serialClient) {
    if (rxId == CAN_ID_REQ_NONCE) {
        _synced = false; 
        _nonce = random(1000, 999999);
        
        MCP_CAN* can = (MCP_CAN*)rxBuf; // Nota d'uso interna fittizia per recuperare l'istanza passata via puntatore, ma usiamo l'overload pulito nel file principale
    }
    else if (rxId == CAN_ID_SEND_HASH && len >= 8) {
        uint8_t hashAttesoBuf[8];
        calcolaHash(_nonce, hashAttesoBuf);
        
        bool autenticato = true;
        for(int i = 0; i < 8; i++) {
            if(rxBuf[i] != hashAttesoBuf[i]) {
                autenticato = false;
                break;
            }
        }
                                
        if (autenticato) {
            _synced = true;
            if(serialClient) serialClient->println(F("[LIBRERIA RX] Autenticazione riuscita!"));
        } else {
            _synced = false;
            if(serialClient) serialClient->println(F("[LIBRERIA RX] Errore Hash. Rifiutato."));
        }
    }
}

void sync_nodes::gestisciTimeoutRX(void* canInstance, Stream* serialClient) {
    // Se la libreria riceve una richiesta esplicita (intercettata in updateRX), risponde con il nonce
    // Gestione interna delegata allo sketch principale per evitare collisioni di invio spontanee
    if (!_synced && (millis() - _ultimoTentativoSincro >= 2000)) {
        _ultimoTentativoSincro = millis();
        inviaRichiestaInizializzazione(canInstance);
    }
}
