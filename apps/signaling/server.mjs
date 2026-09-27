import http from "node:http";
import crypto from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";
import { pool, initDatabase } from "./db.mjs";

const root=dirname(fileURLToPath(import.meta.url));
const webRoot=join(root,"../web");
const port=Number(process.env.PORT||8787);
const sessionSecret=process.env.SESSION_SECRET||"dev-only-change-this";
const peers=new Map();

function passwordHash(password,salt=crypto.randomBytes(16).toString("hex")){return{salt,hash:crypto.scryptSync(password,salt,64).toString("hex")}}
function verifyPassword(password,a){const h=crypto.scryptSync(password,a.salt,64),e=Buffer.from(a.password_hash,"hex");return h.length===e.length&&crypto.timingSafeEqual(h,e)}
function tokenHash(token){return crypto.createHash("sha256").update(token).digest("hex")}
function createToken(){return crypto.randomBytes(32).toString("hex")}
async function getSession(req){const c=req.headers.cookie||"";const t=(c.match(/(?:^|;\\s*)idors_session=([^;]+)/)||[])[1];if(!t)return null;const r=await pool.query("SELECT account_id FROM sessions WHERE token_hash=$1",[tokenHash(t)]);return r.rows[0]||null}
const server=http.createServer(async(req,res)=>{
  if(req.url==="/health")return json(res,200,{ok:true,service:"idors-signaling"});
  if(req.url==="/api/register"||req.url==="/api/login"){
  let body="";req.on("data",c=>body+=c);req.on("end",async()=>{
    try{
      const {username,password}=JSON.parse(body||"{}");
      if(!/^[a-zA-Z0-9_]{3,24}$/.test(username)||typeof password!=="string"||password.length<8)return json(res,400,{ok:false,error:"invalid"});
      let account;
      if(req.url==="/api/register"){
        const exists=await pool.query("SELECT id FROM accounts WHERE username=$1",[username]);
        if(exists.rowCount)return json(res,409,{ok:false,error:"exists"});
        const p=passwordHash(password),id=crypto.randomUUID();
        await pool.query("INSERT INTO accounts(id,username,salt,password_hash) VALUES($1,$2,$3,$4)",[id,username,p.salt,p.hash]);
        await pool.query("INSERT INTO profiles(account_id,display_name,peer_code) VALUES($1,$2,$3)",[id,username,username.toUpperCase().slice(0,12)]);
        account={id,username};
      }else{
        const q=await pool.query("SELECT id,username,salt,password_hash FROM accounts WHERE username=$1",[username]);
        if(!q.rowCount||!verifyPassword(password,q.rows[0]))return json(res,401,{ok:false,error:"invalid"});
        account=q.rows[0];
      }
      const token=createToken();
      await pool.query("DELETE FROM sessions WHERE account_id=$1",[account.id]);
      await pool.query("INSERT INTO sessions(token_hash,account_id) VALUES($1,$2)",[tokenHash(token),account.id]);
      return json(res,200,{ok:true,username:account.username},{"set-cookie":`idors_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/`});
    }catch(e){console.error(e);return json(res,500,{ok:false,error:"server"})}
  });return;
}
if(req.url==="/api/logout"){
  const s=await getSession(req);if(s)await pool.query("DELETE FROM sessions WHERE account_id=$1",[s.account_id]);
  res.writeHead(200,{"set-cookie":"idors_session=; Max-Age=0; Path=/"});return res.end("ok")
}
const file=req.url==="/"?"index.html":req.url.slice(1);
  try{const body=await readFile(join(webRoot,file));res.writeHead(200,{"content-type":file.endsWith(".js")?"text/javascript":"text/html; charset=utf-8"});res.end(body)}catch{res.writeHead(404);res.end("Not found")}
});
const wss=new WebSocketServer({server});
const send=(ws,data)=>ws.readyState===1&&ws.send(JSON.stringify(data));
wss.on("connection",(ws,req)=>{
  const session=await getSession(req);
  if(!session){ws.close(4001,"AUTH_REQUIRED");return}
  const aq=await pool.query("SELECT username FROM accounts WHERE id=$1",[session.account_id]);
  const username=aq.rows[0]?.username;
  if(!username){ws.close(4001,"AUTH_REQUIRED");return}
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