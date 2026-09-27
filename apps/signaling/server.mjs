import http from "node:http";
import crypto from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";

const root=dirname(fileURLToPath(import.meta.url));
const webRoot=join(root,"../web");
const port=Number(process.env.PORT||8787);
const dataDir=process.env.IDORS_DATA_DIR||join(root,"../../data");
const accountsFile=join(dataDir,"accounts.json");
const sessionSecret=process.env.SESSION_SECRET||"dev-only-change-this";
const accounts=new Map(),sessions=new Map(),peers=new Map();

async function loadAccounts(){try{const raw=await readFile(accountsFile,"utf8");for(const a of JSON.parse(raw))accounts.set(a.username,a)}catch{}}
async function saveAccounts(){await mkdir(dataDir,{recursive:true});await writeFile(accountsFile,JSON.stringify([...accounts.values()],null,2))}
function passwordHash(password,salt=crypto.randomBytes(16).toString("hex")){return{salt,hash:crypto.scryptSync(password,salt,64).toString("hex")}}
function verifyPassword(password,a){const h=crypto.scryptSync(password,a.salt,64),e=Buffer.from(a.passwordHash,"hex");return h.length===e.length&&crypto.timingSafeEqual(h,e)}
function createSession(username){const token=crypto.createHmac("sha256",sessionSecret).update(username+":"+Date.now()+":"+crypto.randomUUID()).digest("hex");sessions.set(token,{username});return token}
function getSession(req){const c=req.headers.cookie||"";const t=(c.match(/(?:^|;\\s*)idors_session=([^;]+)/)||[])[1];return t?sessions.get(t):null}
function json(res,status,data,headers={}){res.writeHead(status,{"content-type":"application/json",...headers});res.end(JSON.stringify(data))}
await loadAccounts();

const server=http.createServer(async(req,res)=>{
  if(req.url==="/health")return json(res,200,{ok:true,service:"idors-signaling"});
  if(req.url==="/api/register"||req.url==="/api/login"){
    let body="";req.on("data",c=>body+=c);req.on("end",async()=>{
      try{
        const {username,password}=JSON.parse(body||"{}");
        if(!/^[a-zA-Z0-9_]{3,24}$/.test(username)||typeof password!=="string"||password.length<8)return json(res,400,{ok:false,error:"invalid"});
        let account=accounts.get(username);
        if(req.url==="/api/register"){if(account)return json(res,409,{ok:false,error:"exists"});const p=passwordHash(password);account={username,salt:p.salt,passwordHash:p.hash};accounts.set(username,account);await saveAccounts()}
        else if(!account||!verifyPassword(password,account))return json(res,401,{ok:false,error:"invalid"});
        const token=createSession(username);return json(res,200,{ok:true,username},{"set-cookie":`idors_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/`});
      }catch{return json(res,400,{ok:false,error:"invalid"})}
    });return;
  }
  if(req.url==="/api/logout"){const s=getSession(req);if(s)for(const[t,v]of sessions)if(v.username===s.username)sessions.delete(t);res.writeHead(200,{"set-cookie":"idors_session=; Max-Age=0; Path=/"});return res.end("ok")}
  const file=req.url==="/"?"index.html":req.url.slice(1);
  try{const body=await readFile(join(webRoot,file));res.writeHead(200,{"content-type":file.endsWith(".js")?"text/javascript":"text/html; charset=utf-8"});res.end(body)}catch{res.writeHead(404);res.end("Not found")}
});
const wss=new WebSocketServer({server});
const send=(ws,data)=>ws.readyState===1&&ws.send(JSON.stringify(data));
wss.on("connection",(ws,req)=>{
  const session=getSession(req);
  if(!session){ws.close(4001,"AUTH_REQUIRED");return}
  const username=session.username;
  if([...peers.values()].some(p=>p.username===username)){send(ws,{type:"already-online"});ws.close(4002,"ACCOUNT_ALREADY_CONNECTED");return}
  let id=null;
  send(ws,{type:"auth-ok",username});
  ws.on("message",raw=>{
    let m;try{m=JSON.parse(raw.toString())}catch{return}
    if(m.type==="register"&&typeof m.peerId==="string"){
      id=m.peerId;peers.set(id,{ws,username});send(ws,{type:"welcome",peerId:id});
      for(const[otherId,other]of peers)if(otherId!==id){send(ws,{type:"peer",peerId:otherId});send(other.ws,{type:"peer",peerId:id})}
      return;
    }
    if(!id)return;
    if(m.type==="signal"&&typeof m.to==="string"){const target=peers.get(m.to);if(target)send(target.ws,{type:"signal",from:id,data:m.data})}
  });
  ws.on("close",()=>{if(!id||peers.get(id)?.ws!==ws)return;peers.delete(id);for(const p of peers.values())send(p.ws,{type:"peer-left",peerId:id})});
});
server.listen(port,"0.0.0.0",()=>console.log(`iDOrs signaling on port ${port}`));