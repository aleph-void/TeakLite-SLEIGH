// Black-box single-step driver around teakra (MIT): reads cases, runs one instruction, prints state.
// Input line: "<opcode hex> <expansion hex> [name=hex ...]"; output: "name=hex ..." of all state + changed memory.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <map>
#include <string>
#include <vector>
#include <functional>
#include <unistd.h>
#include <sys/wait.h>
#include <stdexcept>
#include <signal.h>
#include "teakra/teakra.h"
#include "teakra/impl/register.h"
using namespace Teakra;
using u16=uint16_t; using u32=uint32_t; using u64=uint64_t;
static const u32 WLO=0x0000, WHI=0x3000;
static u16 memf(u32 a){ u32 h=a*40503u; return (u16)((h^(h>>7)^(a>>3)*7919u)^0x5a5a); }
struct Field{ std::string name; std::function<u64(RegisterState&)> get; std::function<void(RegisterState&,u64)> set; };
#define F16(n) {#n,[](RegisterState&r){return (u64)r.n;},[](RegisterState&r,u64 v){r.n=(u16)v;}}
#define A16(n,i) {#n #i,[](RegisterState&r){return (u64)r.n[i];},[](RegisterState&r,u64 v){r.n[i]=(u16)v;}}
#define ACC(n,i) {#n #i,[](RegisterState&r){return (u64)(r.n[i]&0xFFFFFFFFFFull);},[](RegisterState&r,u64 v){ v&=0xFFFFFFFFFFull; if(v>>39&1) v|=~0xFFFFFFFFFFull; r.n[i]=v;}}
static std::vector<Field> fields(){
  std::vector<Field> f={
   F16(repc),F16(sat),F16(sata),F16(s),F16(sv),F16(fz),F16(fm),F16(fn),F16(fv),F16(fe),F16(fc0),F16(fc1),F16(flm),F16(fvl),F16(fr),
   F16(vtr0),F16(vtr1),F16(hwm),F16(mixp),F16(sp),F16(page),F16(pcmhi),F16(stepi),F16(stepj),F16(modi),F16(modj),F16(stepi0),F16(stepj0),
   F16(stp16),F16(cmd),F16(epi),F16(epj),F16(prpage),F16(cpc),F16(ccnta),F16(crep),F16(bcn),F16(lp),F16(ie),F16(imv),F16(nimc),F16(p0h_cbs),
   F16(r0b),F16(r1b),F16(r4b),F16(r7b),F16(stepib),F16(stepjb),F16(modib),F16(modjb),F16(stepi0b),F16(stepj0b),
   {"pc",[](RegisterState&r){return (u64)r.pc;},[](RegisterState&r,u64 v){r.pc=(u32)v;}},
   {"rep",[](RegisterState&r){return (u64)r.rep;},[](RegisterState&r,u64 v){r.rep=v;}},
  };
  for(int i=0;i<2;i++){}
  #define ADDACC(n,i) f.push_back(ACC(n,i));
  ADDACC(a,0) ADDACC(a,1) ADDACC(b,0) ADDACC(b,1)
  f.push_back({"a1s",[](RegisterState&r){return (u64)(r.a1s&0xFFFFFFFFFFull);},[](RegisterState&r,u64 v){v&=0xFFFFFFFFFFull; if(v>>39&1) v|=~0xFFFFFFFFFFull; r.a1s=v;}});
  f.push_back({"b1s",[](RegisterState&r){return (u64)(r.b1s&0xFFFFFFFFFFull);},[](RegisterState&r,u64 v){v&=0xFFFFFFFFFFull; if(v>>39&1) v|=~0xFFFFFFFFFFull; r.b1s=v;}});
  #define ADDARR(n,N) for(int i=0;i<N;i++){ int j=i; f.push_back({std::string(#n)+std::to_string(i),[j](RegisterState&r){return (u64)r.n[j];},[j](RegisterState&r,u64 v){r.n[j]=(u16)v;}}); }
  ADDARR(x,2) ADDARR(y,2) ADDARR(pe,2) ADDARR(ps,2) ADDARR(r,8) ADDARR(m,8) ADDARR(br,8)
  ADDARR(arstep,4) ADDARR(arpstepi,4) ADDARR(arpstepj,4) ADDARR(aroffset,4) ADDARR(arpoffseti,4) ADDARR(arpoffsetj,4)
  ADDARR(arrn,4) ADDARR(arprni,4) ADDARR(arprnj,4) ADDARR(ip,3) ADDARR(im,3) ADDARR(ic,3) ADDARR(ext,4) ADDARR(iu,2) ADDARR(ou,5)
  for(int i=0;i<2;i++){ int j=i; f.push_back({"p"+std::to_string(i),[j](RegisterState&r){return (u64)r.p[j];},[j](RegisterState&r,u64 v){r.p[j]=(u32)v;}}); }
  for(int i=0;i<4;i++){ int j=i;
    f.push_back({"bk"+std::to_string(i)+"s",[j](RegisterState&r){return (u64)r.bkrep_stack[j].start;},[j](RegisterState&r,u64 v){r.bkrep_stack[j].start=(u32)v;}});
    f.push_back({"bk"+std::to_string(i)+"e",[j](RegisterState&r){return (u64)r.bkrep_stack[j].end;},[j](RegisterState&r,u64 v){r.bkrep_stack[j].end=(u32)v;}});
    f.push_back({"bk"+std::to_string(i)+"l",[j](RegisterState&r){return (u64)r.bkrep_stack[j].lc;},[j](RegisterState&r,u64 v){r.bkrep_stack[j].lc=(u16)v;}});
  }
  return f;
}
int main(){
  auto fl=fields(); std::map<std::string,int> idx; for(size_t i=0;i<fl.size();i++) idx[fl[i].name]=i;
  std::string line;
  std::vector<u16> init(WHI-WLO);
  for(u32 a=WLO;a<WHI;a++) init[a-WLO]=memf(a);
  Teakra::Teakra t(UserConfig{});
  for(u32 a=WLO;a<WHI;a++) t.DataWrite(a,init[a-WLO],true);
  for(u32 a=0;a<0x3000;a++) t.ProgramWrite(a,memf(a+0x10000));
  while(std::getline(std::cin,line)){
    std::istringstream is(line); unsigned op,ex; if(!(is>>std::hex>>op>>ex)) continue;
    fflush(stdout);
    pid_t pid=fork();
    if(pid==0){
      signal(SIGABRT,[](int){ _exit(134); }); signal(SIGSEGV,[](int){ _exit(139); });
      auto& r=t.GetRegisterState(); r.Reset();
      std::string kv; while(is>>kv){ auto p=kv.find('='); std::string n=kv.substr(0,p); u64 v=strtoull(kv.c_str()+p+1,0,16);
        if(!idx.count(n)){ fprintf(stderr,"unknown field %s\n",n.c_str()); _exit(2); } fl[idx[n]].set(r,v);} 
      u32 pc=r.pc; t.ProgramWrite(pc|(r.prpage<<18),op); t.ProgramWrite((pc+1)|(r.prpage<<18),ex); t.ProgramWrite((pc+2)|(r.prpage<<18),0);
      std::string ex_msg;
      try{ t.Run(1);}catch(std::exception&e){ ex_msg=" EXC"; }
      std::string out; char buf[64]; snprintf(buf,sizeof buf,"%04x %04x%s",op,ex,ex_msg.c_str()); out+=buf;
      for(auto&f:fl){ snprintf(buf,sizeof buf," %s=%llx",f.name.c_str(),(unsigned long long)f.get(r)); out+=buf; }
      for(u32 a=WLO;a<WHI;a++){ u16 v=t.DataRead(a,true); if(v!=init[a-WLO]){ snprintf(buf,sizeof buf," mem%x=%x",a,v); out+=buf; } }
      for(u32 a=0;a<0x3000;a++){ u16 v=t.ProgramRead(a); if(v!=memf(a+0x10000)){ snprintf(buf,sizeof buf," pmem%x=%x",a,v); out+=buf; } }
      out+="\n"; if(write(1,out.data(),out.size())<0) _exit(3); _exit(0);
    }
    int st=0; waitpid(pid,&st,0);
    if(!WIFEXITED(st)||WEXITSTATUS(st)!=0){ printf("%04x %04x CRASH\n",op,ex); fflush(stdout);} 
  }
}
