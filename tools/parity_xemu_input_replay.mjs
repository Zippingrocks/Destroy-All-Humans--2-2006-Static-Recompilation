/* Background-only logical Xbox pad replay for DAH2 retail xemu.
 * Hooks the original XDK XInputGetState entry point. It changes only the API
 * result/return, never menu, save, animation, renderer, or progression state.
 * Debugger stops perturb wall-clock timing, so use this for state routing and
 * run capture-free traces separately when certifying timing. */
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import {performance} from 'node:perf_hooks';
import {RspClient} from './parity_rsp_client.mjs';

const args=process.argv.slice(2);
const option=(key,fallback)=>args.includes(key)?args[args.indexOf(key)+1]:fallback;
const script=option('--script');
const out=option('--out');
const port=Number(option('--port','1236'));
const seconds=Number(option('--seconds','5'));
const bootSeconds=Number(option('--boot-seconds','0'));
const watchText=option('--watch-address',null);
const watchAddress=watchText===null?null:Number(watchText);
const watchKind=option('--watch-kind','write');
const watchTypes={write:2,read:3,access:4};
const leaveStopped=args.includes('--leave-stopped');
if(!script||!out)throw new Error('--script and --out are required');
if(!fs.existsSync(script)||fs.existsSync(out))throw new Error('script must exist and output must be new');
if(!Number.isSafeInteger(port)||port<1||port>65535)throw new Error('invalid port');
if(!Number.isFinite(seconds)||seconds<1||seconds>60)throw new Error('invalid seconds');
if(!Number.isFinite(bootSeconds)||bootSeconds<0||bootSeconds>120)throw new Error('invalid boot seconds');
if(watchAddress!==null&&(!Number.isSafeInteger(watchAddress)||watchAddress<0||watchAddress>0xffffffff))throw new Error('invalid watch address');
if(!(watchKind in watchTypes))throw new Error('--watch-kind must be write, read, or access');

const events=[];
for(const raw of fs.readFileSync(script,'utf8').split(/\r?\n/)){
 const line=raw.trim();
 if(!line||line.startsWith('#'))continue;
 const fields=line.split(/\s+/);
 if(![9,15].includes(fields.length))throw new Error('input rows require 9 or 15 fields');
 if(fields.some((value,index)=>!(index===2 ? /^(?:0x)?[0-9a-f]+$/i.test(value) : /^-?\d+$/.test(value))))throw new Error('invalid numeric token');
 const values=fields.map((value,index)=>parseInt(value,index===2?16:10));
 const [start,duration,buttons,a,b,lx,ly,rx,ry,x=0,y=0,black=0,white=0,lt=0,rt=0]=values;
 if(start<0||duration<1||start>1000000||duration>100000||buttons<0||buttons>65535||
    [a,b,x,y,black,white,lt,rt].some(value=>value<0||value>255)||
    [lx,ly,rx,ry].some(value=>value< -32768||value>32767))throw new Error('input outside controller range');
 events.push({start,duration,buttons,analog:[a,b,x,y,black,white,lt,rt],sticks:[lx,ly,rx,ry]});
}

const fd=fs.openSync(out,'wx');
const trace={schema:1,source:'dah2-xemu-logical-pad',port,script:path.resolve(script),
 inputBoundary:'0x00296224',watchAddress:watchAddress===null?null:`0x${watchAddress.toString(16).padStart(8,'0')}`,watchKind,startedAt:new Date().toISOString(),events:[],
 callers:{},
 deltas:{},
 processed:[],
 limitation:'Synthetic XPP API results; excludes physical-controller fidelity and wall-clock timing because debugger stops perturb execution'};
const socket=net.createConnection({host:'127.0.0.1',port});
socket.setNoDelay(true);
await new Promise((resolve,reject)=>{socket.once('connect',resolve);socket.once('error',reject);});
const rsp=new RspClient(socket);
const inputSite=0x296224;
let armed=false,watchArmed=false,running=false,samples=0,packet=0,lastPad='';
async function read(address,length){
 const reply=await rsp.packet(`m${address.toString(16)},${length.toString(16)}`);
 if(!/^[0-9a-f]+$/i.test(reply)||reply.length!==length*2)throw new Error(`guest read failed at 0x${address.toString(16)}`);
 return Buffer.from(reply,'hex');
}
async function write(address,data){
 const reply=await rsp.packet(`M${address.toString(16)},${data.length.toString(16)}:${data.toString('hex')}`);
 if(reply!=='OK')throw new Error(`guest write failed at 0x${address.toString(16)}`);
}
try{
 let supported=await rsp.packet('qSupported:multiprocess+;swbreak+');
 if(/^[ST]/.test(supported))supported=await rsp.packet('qSupported:multiprocess+;swbreak+');
 let codeReply=await rsp.packet(`m${inputSite.toString(16)},10`);
 if(!/^[0-9a-f]{32}$/i.test(codeReply)){
  socket.write(Buffer.from([3]));
  const stop=await rsp.nextPacket(10000);
  if(!/^[ST]/.test(stop))throw new Error(`could not stop guest: ${stop}`);
  codeReply=await rsp.packet(`m${inputSite.toString(16)},10`);
 }
 const expectedInputCode='535633dbff1510b629008b54240c8b8a';
 if(codeReply.toLowerCase()!==expectedInputCode&&bootSeconds>0){
  const bootDeadline=performance.now()+bootSeconds*1000;
  do{
   rsp.resume();running=true;
   await new Promise(resolve=>setTimeout(resolve,250));
   socket.write(Buffer.from([3]));
   const stop=await rsp.nextPacket(10000);running=false;
   if(!/^[ST]/.test(stop))throw new Error('could not stop booting guest: '+stop);
   codeReply=await rsp.packet('m'+inputSite.toString(16)+',10');
  }while(codeReply.toLowerCase()!==expectedInputCode&&performance.now()<bootDeadline);
 }
 if(codeReply.toLowerCase()!==expectedInputCode)throw new Error('unexpected DAH2 XInputGetState bytes: '+codeReply);
 if(await rsp.packet(`Z1,${inputSite.toString(16)},1`)!=='OK')throw new Error('hardware breakpoint rejected');
 armed=true;
 if(watchAddress!==null){
  if(await rsp.packet(`Z${watchTypes[watchKind]},${watchAddress.toString(16)},4`)!=='OK')throw new Error('hardware watchpoint rejected');
  watchArmed=true;
 }
 const deadline=performance.now()+seconds*1000;
 rsp.resume();running=true;
 while(performance.now()<deadline){
  let stop;
  try{stop=await rsp.nextPacket(Math.max(1,deadline-performance.now()));}
  catch(error){if(error.message.includes('timed out'))break;throw error;}
  running=false;
  if(!/^[ST]/.test(stop))continue;
  const rawRegisters=await rsp.packet('g');
  if(!/^[0-9a-f]+$/i.test(rawRegisters)||rawRegisters.length<80)throw new Error('unexpected i386 register packet');
  const registers=Buffer.from(rawRegisters,'hex');
  const eip=registers.readUInt32LE(32),esp=registers.readUInt32LE(16);
  if(eip!==inputSite){
   if(watchAddress===null)throw new Error(`unexpected breakpoint stop at 0x${eip.toString(16)}`);
   trace.watchHit={eip:`0x${eip.toString(16).padStart(8,'0')}`,esp:`0x${esp.toString(16).padStart(8,'0')}`,
    registers:rawRegisters,code:(await read((eip-32)>>>0,96)).toString('hex'),
    stack:(await read(esp,128)).toString('hex'),matrix:(await read(watchAddress,64)).toString('hex')};
   break;
  }
  const stack=await read(esp,12),ret=stack.readUInt32LE(0),state=stack.readUInt32LE(8);
  const caller=`0x${ret.toString(16).padStart(8,'0')}`;
  trace.callers[caller]=(trace.callers[caller]||0)+1;
  const deltaBits=(await read((esp+0x38)>>>0,4)).readUInt32LE(0);
  const delta=`0x${deltaBits.toString(16).padStart(8,'0')}`;
  trace.deltas[delta]=(trace.deltas[delta]||0)+1;
  if(samples<4)trace.processed.push({sample:samples,bytes:(await read(0x0030f42c,32)).toString('hex')});
  const pad=Buffer.alloc(22);
  for(const event of events){
   if(samples<event.start||samples>=event.start+event.duration)continue;
   pad.writeUInt16LE(pad.readUInt16LE(4)|event.buttons,4);
   event.analog.forEach((value,index)=>{if(value)pad[6+index]=value;});
   event.sticks.forEach((value,index)=>{if(value)pad.writeInt16LE(value,14+index*2);});
  }
  const signature=pad.subarray(4).toString('hex');
  if(signature!==lastPad){lastPad=signature;++packet;trace.events.push({sample:samples,pad:signature});}
  pad.writeUInt32LE(packet,0);
  await write(state,pad);
  registers.writeUInt32LE(0,0);
  registers.writeUInt32LE((esp+12)>>>0,16);
  registers.writeUInt32LE(ret,32);
  if(await rsp.packet('G'+registers.toString('hex'))!=='OK')throw new Error('controller return rejected');
  ++samples;
  rsp.resume();running=true;
 }
 if(!samples)throw new Error('no controller polls observed');
}catch(error){trace.error=error.message;process.exitCode=1;}
finally{
 if(running){socket.write(Buffer.from([3]));try{await rsp.nextPacket(5000);}catch{}}
 if(armed)try{await rsp.packet(`z1,${inputSite.toString(16)},1`);}catch{}
 if(watchArmed)try{await rsp.packet(`z${watchTypes[watchKind]},${watchAddress.toString(16)},4`);}catch{}
 if(!leaveStopped)rsp.resume();
 rsp.close();
 trace.samples=samples;trace.finishedAt=new Date().toISOString();
 fs.writeSync(fd,JSON.stringify(trace,null,2)+'\n');fs.closeSync(fd);
 console.log(JSON.stringify(trace));
}
