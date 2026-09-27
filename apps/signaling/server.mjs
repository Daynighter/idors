import http from "node:http";
import crypto from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";

const root=dirname(fileURLToPath(import.meta.url));
const webRoot=join(root,"../web");
const dataDir=join(root,"../../data");
const dataFile=join(dataDir,"idors.json");
const port=Number(process.env.PORT||8787);
const peers=new Map();
let db={accounts:[],sessions:[],profiles:[],contacts:[],messages:[]};

async function loadDB(){await mkdir(dataDir,{recursive:true});try{db=JSON.parse(await readFile(dataFile,"utf8"));}catch{await saveDB();}}
async function saveDB(){await writeFile(dataFile,JSON.stringify(db,null,2),"utf8");}
function json(res,status,data,headers={}){res.writeHead(status,{"content-type":"application/json; charset=utf-8",...headers});res.end(JSON.stringify(data));}
function passwordHash(password,salt=crypto.randomBytes(16).toString("hex")){return{salt,hash:crypto.scryptSync(password,salt,64).toString("hex")}}
function verifyPassword(password,a){const h=crypto.scryptSync(password,a.salt,64),e=Buffer.from(a.password_hash,"hex");return h.length===e.length&&crypto.timingSafeEqual(h,e)}
function tokenHash(token){return crypto.createHash("sha256").update(token).digest("hex")}
function createToken(){return crypto.randomBytes(32).toString("hex")}
function getCookie(req){const c=req.headers.cookie||"";return(c.match(/(?:^|;\s*)idors_session=([^;]+)/)||[])[1]||null}
function getSession(req){const t=getCookie(req);if(!t)return null;const s=db.sessions.find(x=>x.token_hash===tokenHash(t));return s||null}
function body(req){return new Promise((resolve,reject)=>{let b="";req.on("data",c=>b+=c);req.on("end",()=>{try{resolve(JSON.parse(b||"{}"))}catch{reject(new Error("invalid json"))}});req.on("error",reject)})}
function uniquePeerCode(){let code;do{code="#"+String(Math.floor(Math.random()*100000)).padStart(5,"0")}while(db.profiles.some(p=>p.peer_code===code));return code}

const server=http.createServer(async(req,res)=>{
  try{
    const url=new URL(req.url,"http://idors.local");
    if(url.pathname==="/health")return json(res,200,{ok:true,service:"idors"});
    if(url.pathname==="/api/register"&&req.method==="POST"){
      const {username,password}=await body(req);
      if(!/^[a-zA-Z0-9_]{3,24}$/.test(username)||typeof password!=="string"||password.length<8)return json(res,400,{ok:false,error:"invalid"});
      if(db.accounts.some(a=>a.username===username))return json(res,409,{ok:false,error:"exists"});
      const id=crypto.randomUUID(),p=passwordHash(password),peerCode=uniquePeerCode();
      db.accounts.push({id,username,salt:p.salt,password_hash:p.hash,created_at:new Date().toISOString()});
      db.profiles.push({account_id:id,display_name:username,peer_code:peerCode,avatar_url:null,bio:null,updated_at:new Date().toISOString()});
      const token=createToken();db.sessions.push({token_hash:tokenHash(token),account_id:id,created_at:new Date().toISOString()});
      await saveDB();
      return json(res,200,{ok:true,username,peerCode},{"set-cookie":`idors_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/`});
    }
    if(url.pathname==="/api/login"&&req.method==="POST"){
      const {username,password}=await body(req);const a=db.accounts.find(x=>x.username===username);
      if(!a||!verifyPassword(password,a))return json(res,401,{ok:false,error:"invalid"});
      db.sessions=db.sessions.filter(s=>s.account_id!==a.id);const token=createToken();db.sessions.push({token_hash:tokenHash(token),account_id:a.id,created_at:new Date().toISOString()});await saveDB();
      return json(res,200,{ok:true,username:a.username},{"set-cookie":`idors_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/`});
    }
    if(url.pathname==="/api/me"){const s=getSession(req);if(!s)return json(res,401,{ok:false});const a=db.accounts.find(x=>x.id===s.account_id),p=db.profiles.find(x=>x.account_id===s.account_id);return json(res,200,{ok:true,profile:{id:a.id,username:a.username,...p}})}
    if(url.pathname==="/api/contacts"&&req.method==="GET"){const s=getSession(req);if(!s)return json(res,401,{ok:false});const ids=db.contacts.filter(c=>c.account_id===s.account_id).map(c=>c.contact_account_id);const contacts=ids.map(id=>{const a=db.accounts.find(x=>x.id===id),p=db.profiles.find(x=>x.account_id===id);return a?{username:a.username,...p}:null}).filter(Boolean);return json(res,200,{ok:true,contacts})}
    if(url.pathname==="/api/contacts"&&req.method==="POST"){const s=getSession(req);if(!s)return json(res,401,{ok:false});const {peerCode}=await body(req);const p=db.profiles.find(x=>x.peer_code===peerCode);if(!p)return json(res,404,{ok:false,error:"not_found"});if(p.account_id===s.account_id)return json(res,400,{ok:false,error:"self"});if(!db.contacts.some(c=>c.account_id===s.account_id&&c.contact_account_id===p.account_id))db.contacts.push({account_id:s.account_id,contact_account_id:p.account_id,created_at:new Date().toISOString()});await saveDB();return json(res,200,{ok:true})}
    if(url.pathname==="/api/messages"&&req.method==="GET"){const s=getSession(req);if(!s)return json(res,401,{ok:false});const peer=url.searchParams.get("peer"),p=db.profiles.find(x=>x.peer_code===peer);if(!p)return json(res,404,{ok:false,error:"not_found"});const messages=db.messages.filter(m=>(m.sender_id===s.account_id&&m.recipient_id===p.account_id)||(m.sender_id===p.account_id&&m.recipient_id===s.account_id));return json(res,200,{ok:true,messages})}
    if(url.pathname==="/api/messages"&&req.method==="POST"){const s=getSession(req);if(!s)return json(res,401,{ok:false});const {peerCode,message}=await body(req);if(typeof message!=="string"||!message.trim()||message.length>4000)return json(res,400,{ok:false,error:"invalid"});const p=db.profiles.find(x=>x.peer_code===peerCode);if(!p)return json(res,404,{ok:false,error:"not_found"});const m={id:crypto.randomUUID(),sender_id:s.account_id,recipient_id:p.account_id,body:message.trim(),created_at:new Date().toISOString()};db.messages.push(m);await saveDB();return json(res,201,{ok:true,message:m})}
    if(url.pathname==="/api/logout"){const s=getSession(req);if(s){db.sessions=db.sessions.filter(x=>x.account_id!==s.account_id);await saveDB();}res.writeHead(200,{"set-cookie":"idors_session=; Max-Age=0; Path=/"});return res.end("ok")}
    const file=url.pathname==="/"?"index.html":url.pathname.slice(1);try{const bodyFile=await readFile(join(webRoot,file));res.writeHead(200,{"content-type":file.endsWith(".js")?"text/javascript":"text/html; charset=utf-8"});return res.end(bodyFile)}catch{return json(res,404,{ok:false,error:"not_found"})}
  }catch(e){console.error(e);return json(res,500,{ok:false,error:"server"})}
});
const wss=new WebSocketServer({server});
const send=(ws,data)=>ws.readyState===1&&ws.send(JSON.stringify(data));
wss.on("connection",(ws,req)=>{
  const s=getSession(req);if(!s){ws.close(4001,"AUTH_REQUIRED");return}
  const a=db.accounts.find(x=>x.id===s.account_id);if(!a){ws.close(4001,"AUTH_REQUIRED");return}
  if([...peers.values()].some(p=>p.accountId===a.id)){send(ws,{type:"already-online"});ws.close(4002,"ACCOUNT_ALREADY_CONNECTED");return}
  let id=null;send(ws,{type:"auth-ok",username:a.username});
  ws.on("message",raw=>{let m;try{m=JSON.parse(raw.toString())}catch{return}
    if(m.type==="register"&&typeof m.peerId==="string"){id=m.peerId;peers.set(id,{ws,accountId:a.id});send(ws,{type:"welcome",peerId:id});for(const[otherId,other]of peers)if(otherId!==id){send(ws,{type:"peer",peerId:otherId});send(other.ws,{type:"peer",peerId:id})}}
    else if(id&&m.type==="signal"&&typeof m.to==="string"){const target=peers.get(m.to);if(target)send(target.ws,{type:"signal",from:id,data:m.data})}
  });
  ws.on("close",()=>{if(!id||peers.get(id)?.ws!==ws)return;peers.delete(id);for(const p of peers.values())send(p.ws,{type:"peer-left",peerId:id})});
});
loadDB().then(()=>server.listen(port,"0.0.0.0",()=>console.log(`iDors listening on ${port}`))).catch(e=>{console.error(e);process.exit(1)});
