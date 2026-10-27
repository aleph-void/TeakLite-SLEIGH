// black-box driver: reads little-endian 16-bit words from stdin as hex pairs (opcode [expansion])
#include <cstdio>
#include <cstdint>
#include "teakra/disassembler.h"
int main(){ unsigned a,b; 
 while(scanf("%x %x",&a,&b)==2){
   std::string s = Teakra::Disassembler::Do((uint16_t)a,(uint16_t)b);
   printf("%04x %04x %d\t%s\n",a,b,(int)Teakra::Disassembler::NeedExpansion((uint16_t)a),s.c_str());
 }}
