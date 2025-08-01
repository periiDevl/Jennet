#include"TCP_HEADER.h"
byte FIN()  { return 1; }
byte SYN()  { return 2; }
byte RST()  { return 4; }
byte PSH()  { return 8; }
byte ACK()  { return 16; }
byte URG()  { return 32; }
byte ECE()  { return 64; }
byte CWR()  { return 128;}
byte SYNACK() { return SYN() | ACK(); }
byte FINACK() { return FIN() | ACK(); }
