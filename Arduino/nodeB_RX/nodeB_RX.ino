#include <sync_nodes.h> 
#include <SPI.h>
#include <mcp_can.h>

extern "C" {
  #include <secure-can.h>
}

#define CAN0_INT 2       
#define CAN_CS_PIN 10
MCP_CAN CAN0(CAN_CS_PIN);                                

long unsigned int rxId;
unsigned char len = 0;
unsigned char rxBuf[8];
byte last_encrypted_data[8] = {0, 0, 0, 0, 0, 0, 0, 0};
byte last_tag[4] = {0, 0, 0, 0};
byte clear_data[8] = {0, 0, 0, 0, 0, 0, 0, 0};

unsigned int s = 0;
unsigned int f = 0;

const uint8_t CHIAVE_SISTEMA[16] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

sync_nodes gestoreSync(CHIAVE_SISTEMA);

void setup() {
  Serial.begin(115200);
  randomSeed(analogRead(1)); 
  
  if(CAN0.begin(MCP_ANY, CAN_500KBPS, MCP_16MHZ) == CAN_OK)
    Serial.println("MCP2515 Initialized Successfully!");
  else
    Serial.println("Error Initializing MCP2515...");

  CAN0.setMode(MCP_NORMAL);                                
  pinMode(CAN0_INT, INPUT);      
  gestoreSync.begin();
}

void loop() {
  gestoreSync.gestisciTimeoutRX(&CAN0, NULL); 

  while(CAN0.checkReceive() == CAN_MSGAVAIL) 
  {
    CAN0.readMsgBuf(&rxId, &len, rxBuf);      

    gestoreSync.updateRX(rxId, len, rxBuf, NULL);

    if (rxId == 0x110) {
       int32_t nuovoNonce = gestoreSync.getNonce(); 
       unsigned char txBuf[4];
       txBuf[0] = (nuovoNonce >> 24) & 0xFF; txBuf[1] = (nuovoNonce >> 16) & 0xFF;
       txBuf[2] = (nuovoNonce >> 8)  & 0xFF; txBuf[3] = nuovoNonce & 0xFF;
       CAN0.sendMsgBuf(0x111, 0, 4, txBuf); 
    }

    if (gestoreSync.isSynced()) {
      int32_t syncNonce = gestoreSync.getNonce();
      
      if (rxId == 0x105) {
        int decrypt_stat = receive_auth_frame(rxBuf, last_encrypted_data, last_tag, clear_data, (uint8_t*)&syncNonce);
        
        if (decrypt_stat == 0) {
          s++;
        } else {
          f++;
        }

        unsigned int totali = s + f;

        // OGNI 100 FRAME: Stampa veloce del nonce condiviso lato RX
        if (totali % 100 == 0) {
          Serial.print(F("[RX] Nonce Condiviso Attuale: "));
          Serial.println(gestoreSync.getNonce());
        }

        // OGNI 1000 FRAME: Resoconto finale e azzeramento
        if (totali == 1000) {
          Serial.print(F("--> STATISTICHE FINALI - Successi su 1000 frame: "));
          Serial.println(s);
          s = 0;
          f = 0;
        }
      }
      else if (rxId == 0x106) {
        memcpy(last_encrypted_data, rxBuf, 8);
      }
    }
  }
}
