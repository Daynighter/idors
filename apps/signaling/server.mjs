import http from "node:http";
import crypto from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";
const root=dirname(fileURLToPath(import.meta.url));
const webRoot=join(root,"../web");
const port=Number(process.env.PORT||8787);
const peers=new Map();
const sessions=new Map();
const accounts=new Map();
const dataDir=process.env.IDORS_DATA_DIR||join(root,"../../data");
const accountsFile=join(dataDir,"accounts.json");
const sessionSecret=process.env.SESSION_SECRET||"change-me-in-production";
async function loadAccounts(){try{const raw=await readFile(accountsFile,"utf8");for(const a of JSON.parse(raw))accounts.set(a.username,a)}catch{}}
async function saveAccounts(){await mkdir(dataDir,{recursive:true});await writeFile(accountsFile,JSON.stringify([...accounts.values()],null,2))}
const hashPassword=(password,salt=crypto.randomBytes(16).toString("hex"))=>({salt,hash:crypto.scryptSync(password,salt,64).toString("hex")});
const verifyPassword=(password,a)=>crypto.timingSafeEqual(Buffer.from(a.passwordHash,"hex"),Buffer.from(crypto.scryptSync(password,a.salt,64).toString("hex"),"hex"));
const tokenFor=(username)=>crypto.createHmac("sha256",sessionSecret).update(username+":"+Date.now()+":"+crypto.randomUUID()).digest("hex");
await loadAccounts();
const server=http.createServer(async(req,res)=>{if(req.url==="/health"){res.writeHead(200,{"content-type":"application/json"});return res.end(JSON.stringify({ok:true,service:"idors-signaling"}));}if(req.url==="/api/register"||req.url==="/api/login"){let body="";req.on("data",c=>body+=c);req.on("end",async()=>{try{const {username,password}=JSON.parse(body);if(!/^[a-zA-Z0-9_]{3,24}$/.test(username)||typeof password!=="string"||password.length<8)throw new Error("invalid");if(req.url==="/api/register"&&accounts.has(username))throw new Error("exists");let account=accounts.get(username);if(req.url==="/api/register"){const p=hashPassword(password);account={username,salt:p.salt,passwordHash:p.hash};accounts.set(username,account);await saveAccounts()}else if(!account||!verifyPassword(password,account))throw new Error("invalid");const token=tokenFor(username);sessions.set(token,{username});res.writeHead(200,{"content-type":"application/json","set-cookie":`idors_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/`});res.end(JSON.stringify({ok:true,username}))}catch(e){res.writeHead(400,{"content-type":"application/json"});res.end(JSON.stringify({ok:false,error:e.message==="exists"?"exists":"invalid"}))}});return}
if(req.url==="/api/logout"){const cookie=req.headers.cookie||"";const token=(cookie.match(/idors_session=([^;]+)/)||[])[1];if(token)sessions.delete(token);res.writeHead(200,{"set-cookie":"idors_session=; Max-Age=0; Path=/"});return res.end("ok")}
const file=req.url==="/"?"index.html":req.url.slice(1);try{const body=await readFile(join(webRoot,file));const type=file.endsWith(".js")?"text/javascript":"text/html; charset=utf-8";res.writeHead(200,{"content-type":type});res.end(body)}catch{res.writeHead(404);res.end("Not found")}});
const wss=new WebSocketServer({server});const send=(ws,data)=>ws.readyState===1&&ws.send(JSON.stringify(data));
wss.on("connection",ws=>{const id=crypto.randomUUID();peers.set(id,{ws,username});send(ws,{type:"welcome",peerId:id});for(const [otherId,other] of peers){
    if(otherId!==id) send(ws,{type:"peer",peerId:otherId});
  }
  for(const [otherId,other] of peers){
    if(otherId!==id) send(other.ws,{type:"peer",peerId:id});
  }ws.on("message",raw=>{let m;try{m=JSON.parse(raw.toString())}catch{return}if(m.type==="auth"&&typeof m.token==="string"){const session=sessions.get(m.token);if(!session){send(ws,{type:"auth-error"});return}username=session.username;if([...peers.values()].some(p=>p.username===username&&p.ws!==ws)){send(ws,{type:"already-online"});return}send(ws,{type:"auth-ok",username});return}
    if(!username)return;
    if(m.type==="register"&&typeof m.peerId==="string"){
      id=m.peerId;
      const previous=peers.get(id);
      if(previous&&previous!==ws){try{previous.close()}catch{}}
      peers.set(id,ws);
      send(ws,{type:"welcome",peerId:id});
      for(const [otherId,other] of peers){
        if(otherId!==id) send(ws,{type:"peer",peerId:otherId});
      }
      for(const [otherId,other] of peers){
        if(otherId!==id) send(other,{type:"peer",peerId:id});
      }
      return;
    }
    if(!id)return;
    if(m.type==="signal"&&typeof m.to==="string"){const target=peers.get(m.to);if(target)send(target.ws,{type:"signal",from:id,data:m.data})}});ws.on("close",()=>{peers.delete(id);for(const other of peers.values())send(other,{type:"peer-left",peerId:id})})});
server.listen(port,()=>console.log(`iDOrs signaling on http://localhost:${port}`));
