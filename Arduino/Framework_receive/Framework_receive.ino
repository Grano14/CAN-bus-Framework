// CAN Receive Example
//

#include <mcp_can.h>
#include <SPI.h>
extern "C" {
  #include <framework.h>
}

long unsigned int rxId;
unsigned char len = 0;
unsigned char rxBuf[8];
char msgString[128];                      

// Impostazione del INT al pin 2 (non è usato)
#define CAN0_INT 2       
// Set pin CS del modulo mcp2515 al pin 10 di arduino
MCP_CAN CAN0(10);                               

// ---DEFINIZIONE VARIABILI GLOBALI---
byte last_encrypted_data[8] = {0, 0, 0, 0, 0, 0, 0, 0};
byte auth_data[8] = {0, 0, 0, 0, 0, 0, 0, 0};
byte last_tag[4] = {0, 0, 0, 0};
byte clear_data[8] = {0, 0, 0, 0, 0, 0, 0, 0};
//------------------------------------

void setup()
{
  Serial.begin(115200);
  
  // Inizializzazione MCP2515 su 16MHz con baudrate di 500kb/s
  if(CAN0.begin(MCP_ANY, CAN_500KBPS, MCP_16MHZ) == CAN_OK)
    Serial.println("MCP2515 Initialized Successfully!");
  else
    Serial.println("Error Initializing MCP2515...");

  // Cambio alla modalità normale per permettere la trasmissione di messaggi
  CAN0.setMode(MCP_NORMAL);                    
  // Configurazione pin per /INT input (non utilizzato)
  pinMode(CAN0_INT, INPUT);                            
  
  Serial.println("MCP2515 starting Receiving Example...");
}

void loop()
{
  // CONTROLLO SOFTWARE: Chiede direttamente al chip MCP2515 se ha messaggi non letti
  while(CAN0.checkReceive() == CAN_MSGAVAIL) 
  {
    // Leggi il messaggio e svuota il buffer
    CAN0.readMsgBuf(&rxId, &len, rxBuf);      

    // Controllo dell'ID
    int decrypt_stat = 0;
    if (rxId == 0x100){
      //Serial.print("Messaggio di auth!");
      // Se auth frame calcola il valore dei dati in chiaro e li valida
      decrypt_stat = receive_auth_frame(rxBuf, last_encrypted_data, last_tag, clear_data);
      //Serial.println(decrypt_stat);
    }
    else{
      //Serial.print("Messaggio dati!");
      memcpy(last_encrypted_data, rxBuf, 8);
    }

    
    /* 
     *  Stampe per diagnosi
    if((rxId & 0x80000000) == 0x80000000)     // Determina se l'ID è standard o esteso
      sprintf(msgString, "Extended ID: 0x%.8lX  DLC: %1d  Data:", (rxId & 0x1FFFFFFF), len);
    else
      sprintf(msgString, "Standard ID: 0x%.3lX       DLC: %1d  Data:", rxId, len);
  
    Serial.print(msgString);
  
    if((rxId & 0x40000000) == 0x40000000){    // Controllo richiesta remota
      sprintf(msgString, " REMOTE REQUEST FRAME");
      Serial.print(msgString);
    } else {
      for(byte i = 0; i<len; i++){
        sprintf(msgString, " 0x%.2X", rxBuf[i]);
        Serial.print(msgString);
      }
    }
    */

    Serial.println();
    // --- STAMPA DELL'ESITO ---
    if (rxId == 0x100){
      Serial.print("Esito Autenticazione: ");
      if (decrypt_stat == 0) {
        Serial.println("SUCCESS [Il Tag corrisponde, i dati sono validi]");
        for(int i = 0; i < 8; i++){
          Serial.print(clear_data[i]);
        }
      } else {
        Serial.println("FAIL [Tag non valido o errore di decifratura]");
      }
      Serial.println();
    }
  }
}

/*********************************************************************************************************
  END FILE
*********************************************************************************************************/
