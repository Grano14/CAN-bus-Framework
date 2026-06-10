// Codice che simula una ECU che trasmette i dati sul CAN bus

#include <mcp_can.h>
#include <SPI.h>
// Import della libreria contenente il codice del framework di sicurezza per invio e ricezione dei dati
extern "C" {
  #include <framework.h>
}

// Set pin CS del modulo mcp2515 al pin 10 di arduino
MCP_CAN CAN0(10);     

// ---VARIABILI GLOBALI---
// Definizione variabili nonce
    byte prev_nonce[4] = {0, 0, 0, 0};
    byte next_nonce[4] = {0, 0, 0, 0};

// Definizione variabile per che contiene l'output della cifratura con ASCON (8 byte cifrati + 4 byte di tag)
    char ciphertext_and_tag[8 + 4];
    
//------------------------

void setup()
{
  Serial.begin(115200);

  // Inizializzazione MCP2515 su 16MHz con baudrate di 500kb/s
  if(CAN0.begin(MCP_ANY, CAN_500KBPS, MCP_16MHZ) == CAN_OK) Serial.println("MCP2515 Initialized Successfully!");
  else Serial.println("Error Initializing MCP2515...");

  // Cambio alla modalità normale per permettere la trasmissione di messaggi
  CAN0.setMode(MCP_NORMAL);  
}

// Dati di esempio statici che vengono inviati dalla ECU
byte data[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

void loop()
{

  // Calcolo dei dati di auth e dei dati cifrati
  byte auth[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  byte encrypted_data[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  // Stampe dei nonce per diagnosi
  /*
  Serial.print("Next Nonce (Generato): [ ");
  for (int i = 0; i < 4; i++) {
    if (next_nonce[i] < 0x10) Serial.print("0");
    Serial.print(next_nonce[i], HEX);
    Serial.print(" ");
  }
  */

  // Calcolo dei dati cifrati e di auth con la funzione del framework
  send_auth_frame(data, auth, encrypted_data, prev_nonce, next_nonce);

  // Invio effettivo dei dati di auth:  ID = 0x100, Standard CAN Frame, Data length = 8 bytes, 'data' = array of data bytes to send
  byte sndStat = CAN0.sendMsgBuf(0x100, 0, 8, auth);
  if(sndStat == CAN_OK){
    Serial.println("Message auth Sent Successfully!");
  } else {
    Serial.println("Error Sending Message...");
  }

  // Invio effettivo dei dati cifrati:  ID = 0x101, Standard CAN Frame, Data length = 8 bytes, 'data' = array of data bytes to send
  sndStat = CAN0.sendMsgBuf(0x101, 0, 8, encrypted_data);
  if(sndStat == CAN_OK){
    Serial.println("Message Data Sent Successfully!");
  } else {
    Serial.println("Error Sending Message...");
  }

  // Stampe dei nonce per diagnosi
  /*
  Serial.print("Next Nonce (Generato): [ ");
  for (int i = 0; i < 4; i++) {
    if (next_nonce[i] < 0x10) Serial.print("0");
    Serial.print(next_nonce[i], HEX);
    Serial.print(" ");
  }
  Serial.println(" ");
  */

  //delay(100);   // send data per 1000ms
  
}

/*********************************************************************************************************
  END FILE
*********************************************************************************************************/
