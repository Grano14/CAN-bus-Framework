#include <sync_nodes.h> 
#include <SPI.h>
#include <mcp_can.h>

extern "C" {
  #include <secure-can.h>
}

#define CAN_CS_PIN 10
MCP_CAN CAN0(CAN_CS_PIN);     

byte prev_nonce[4] = {0, 0, 0, 0};
byte next_nonce[4] = {0, 0, 0, 0};
byte auth[8] = {0, 0, 0, 0, 0, 0, 0, 0};
byte encrypted_data[8] = {0, 0, 0, 0, 0, 0, 0, 0};
char ciphertext_and_tag[8 + 4];

// Contatore per i frame inviati dal TX
unsigned int conteggioFrame = 0;

const uint8_t CHIAVE_SISTEMA[16] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

sync_nodes gestoreSync(CHIAVE_SISTEMA);

byte data[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

void setup() {
  Serial.begin(115200);
  
  if(CAN0.begin(MCP_ANY, CAN_500KBPS, MCP_16MHZ) == CAN_OK) 
    Serial.println("MCP2515 Initialized Successfully!");
  else 
    Serial.println("Error Initializing MCP2515...");

  CAN0.setMode(MCP_NORMAL); 
  gestoreSync.begin();
}

void loop() {
  gestoreSync.gestisciTimeoutTX(&CAN0, NULL); 

  if (CAN0.checkReceive() == CAN_MSGAVAIL) {
    long unsigned int rxId;
    unsigned char len;
    unsigned char rxBuf[8];
    
    CAN0.readMsgBuf(&rxId, &len, rxBuf);
    gestoreSync.updateTX(rxId, len, rxBuf, NULL);
    
    if (rxId == 0x111 && len >= 4) {
       int32_t nonceRicevuto = gestoreSync.getNonce();
       uint8_t mioHashBuf[8];
       
       SHA256 sha256;
       uint8_t hashCompleto[32];
       sha256.reset();
       sha256.update(CHIAVE_SISTEMA, 16);
       sha256.update(&nonceRicevuto, sizeof(nonceRicevuto));
       sha256.finalize(hashCompleto, 32);
       for(int i=0; i<8; i++) mioHashBuf[i] = hashCompleto[i];
       
       CAN0.sendMsgBuf(0x112, 0, 8, mioHashBuf);
    }
  }

  if (gestoreSync.isSynced()) {
      int32_t syncNonce = gestoreSync.getNonce();

      send_auth_frame(data, auth, encrypted_data, prev_nonce, next_nonce, (uint8_t*)&syncNonce);
      
      CAN0.sendMsgBuf(0x105, 0, 8, auth);
      CAN0.sendMsgBuf(0x106, 0, 8, encrypted_data);
      
      // Incrementa il contatore dei frame applicativi inviati
      conteggioFrame++;
      
      // Ogni 100 frame inviati, stampa il nonce
      if (conteggioFrame >= 100) {
        Serial.print(F("[TX] Nonce Condiviso Attuale: "));
        Serial.println(syncNonce);
        conteggioFrame = 0;
      }
  }
}
