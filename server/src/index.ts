import 'dotenv/config';
import express from 'express';
import http from 'http';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import multer from 'multer';
import webpush from 'web-push';
import { WebSocketServer, WebSocket } from 'ws';
import { PrismaClient, DeviceType, PairingStatus } from '@prisma/client';

const prisma = new PrismaClient();
const app = express();
const server = http.createServer(app);
const PORT = Number(process.env.PORT || 8080);
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const uploadDir = path.resolve(process.env.UPLOAD_DIR || './uploads');
fs.mkdirSync(uploadDir, { recursive: true });

app.use(cors({ origin: CLIENT_ORIGIN, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use('/recordings', express.static(uploadDir, { fallthrough: false }));

if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY && process.env.VAPID_SUBJECT) {
  webpush.setVapidDetails(process.env.VAPID_SUBJECT, process.env.VAPID_PUBLIC_KEY, process.env.VAPID_PRIVATE_KEY);
}

const upload = multer({ dest: uploadDir, limits: { fileSize: 100 * 1024 * 1024 } });
const hash = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
const randomCode = () => String(Math.floor(100000 + Math.random() * 900000));
const sign = (userId: string) => jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '7d' });

type AuthedRequest = express.Request & { userId?: string };
function auth(req: AuthedRequest, res: express.Response, next: express.NextFunction) {
  try {
    const token = req.cookies.vk_session || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    const decoded = jwt.verify(token, JWT_SECRET) as { sub: string };
    req.userId = decoded.sub;
    next();
  } catch { res.status(401).json({ error: 'Invalid or expired session' }); }
}

app.get('/health', (_req,res)=>res.json({ok:true, service:'VK SECURITY'}));
app.post('/api/auth/register', async (req,res)=>{
  const { email, password, displayName } = req.body || {};
  if (!email || typeof password !== 'string' || password.length < 8) return res.status(400).json({error:'Use a valid email and a password of at least 8 characters.'});
  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await prisma.user.create({ data: { email: String(email).toLowerCase().trim(), passwordHash, displayName, settings: { create: {} } } });
    res.cookie('vk_session', sign(user.id), { httpOnly:true, sameSite: process.env.COOKIE_SAME_SITE || 'lax', secure:process.env.COOKIE_SECURE==='true', maxAge:7*86400000 });
    res.status(201).json({ user:{id:user.id,email:user.email,displayName:user.displayName} });
  } catch (e:any) { res.status(400).json({error:e?.code==='P2002'?'Email already registered':'Registration failed'}); }
});
app.post('/api/auth/login', async (req,res)=>{
  const { email, password } = req.body || {};
  const user = await prisma.user.findUnique({where:{email:String(email||'').toLowerCase().trim()}});
  if (!user || !(await bcrypt.compare(String(password||''), user.passwordHash))) return res.status(401).json({error:'Invalid email or password'});
  res.cookie('vk_session', sign(user.id), { httpOnly:true, sameSite: process.env.COOKIE_SAME_SITE || 'lax', secure:process.env.COOKIE_SECURE==='true', maxAge:7*86400000 });
  res.json({user:{id:user.id,email:user.email,displayName:user.displayName}});
});
app.post('/api/auth/logout', (_req,res)=>{ res.clearCookie('vk_session'); res.json({ok:true}); });
app.get('/api/auth/me', auth, async (req:AuthedRequest,res)=>{ const u=await prisma.user.findUnique({where:{id:req.userId!},select:{id:true,email:true,displayName:true}}); res.json({user:u}); });

app.post('/api/auth/forgot-password', async (req,res)=>{
  const email=String(req.body?.email||'').toLowerCase().trim();
  const user=await prisma.user.findUnique({where:{email}});
  if (user) { const raw=crypto.randomBytes(32).toString('hex'); await prisma.user.update({where:{id:user.id},data:{resetTokenHash:hash(raw),resetTokenExpiresAt:new Date(Date.now()+30*60*1000)}}); console.log(`DEV password reset for ${email}: ${CLIENT_ORIGIN}/reset-password?token=${raw}`); }
  res.json({ok:true,message:'If that email exists, a reset link has been created.'});
});
app.post('/api/auth/reset-password', async (req,res)=>{
  const {token,password}=req.body||{}; if(!token||typeof password!=='string'||password.length<8)return res.status(400).json({error:'Invalid reset request'});
  const user=await prisma.user.findFirst({where:{resetTokenHash:hash(token),resetTokenExpiresAt:{gt:new Date()}}}); if(!user)return res.status(400).json({error:'Reset link expired or invalid'});
  await prisma.user.update({where:{id:user.id},data:{passwordHash:await bcrypt.hash(password,12),resetTokenHash:null,resetTokenExpiresAt:null}}); res.json({ok:true});
});

app.get('/api/devices', auth, async (req:AuthedRequest,res)=>res.json(await prisma.device.findMany({where:{userId:req.userId!},orderBy:{createdAt:'desc'}})));
app.post('/api/devices', auth, async (req:AuthedRequest,res)=>{
  const {name,type}=req.body||{}; if(!name||![DeviceType.PHONE,DeviceType.LAPTOP].includes(type))return res.status(400).json({error:'Invalid device'});
  const d=await prisma.device.create({data:{userId:req.userId!,name,type,userAgent:req.headers['user-agent']}}); res.status(201).json(d);
});
app.patch('/api/devices/:id', auth, async(req:AuthedRequest,res)=>{ const d=await prisma.device.updateMany({where:{id:req.params.id,userId:req.userId!},data:{name:req.body?.name}}); if(!d.count)return res.status(404).json({error:'Device not found'}); res.json({ok:true}); });
app.delete('/api/devices/:id', auth, async(req:AuthedRequest,res)=>{ const d=await prisma.device.deleteMany({where:{id:req.params.id,userId:req.userId!}}); if(!d.count)return res.status(404).json({error:'Device not found'}); res.json({ok:true}); });

app.post('/api/pairings', auth, async(req:AuthedRequest,res)=>{
  const {cameraDeviceId}=req.body||{}; const d=await prisma.device.findFirst({where:{id:cameraDeviceId,userId:req.userId!}}); if(!d)return res.status(404).json({error:'Camera device not found'});
  await prisma.pairing.updateMany({where:{cameraDeviceId,status:PairingStatus.PENDING},data:{status:PairingStatus.EXPIRED}});
  const code=randomCode(); const qrToken=crypto.randomBytes(24).toString('base64url'); const p=await prisma.pairing.create({data:{userId:req.userId!,cameraDeviceId,codeHash:hash(code),qrTokenHash:hash(qrToken),expiresAt:new Date(Date.now()+5*60*1000)}});
  res.status(201).json({pairingId:p.id,code,qrToken,expiresAt:p.expiresAt});
});
app.post('/api/pairings/approve', auth, async(req:AuthedRequest,res)=>{
  const {code,qrToken,viewerDeviceId}=req.body||{}; const p=await prisma.pairing.findFirst({where:{userId:req.userId!,status:PairingStatus.PENDING,expiresAt:{gt:new Date()},OR:[code?{codeHash:hash(String(code))}:{id:'never'} as any,qrToken?{qrTokenHash:hash(String(qrToken))}:{id:'never'} as any]}});
  if(!p)return res.status(400).json({error:'Pairing code is invalid or expired'});
  const v=await prisma.device.findFirst({where:{id:viewerDeviceId,userId:req.userId!}}); if(!v)return res.status(404).json({error:'Viewer device not found'});
  const updated=await prisma.pairing.update({where:{id:p.id},data:{viewerDeviceId:v.id,status:PairingStatus.APPROVED,approvedAt:new Date()}}); broadcastUser(req.userId!,{type:'pairing-approved',pairingId:updated.id,cameraDeviceId:updated.cameraDeviceId,viewerDeviceId:v.id}); res.json({ok:true,pairingId:updated.id});
});
app.get('/api/pairings',auth,async(req:AuthedRequest,res)=>res.json(await prisma.pairing.findMany({where:{userId:req.userId!},include:{cameraDevice:true,viewerDevice:true},orderBy:{createdAt:'desc'}})));

app.get('/api/events',auth,async(req:AuthedRequest,res)=>{
  const limit=Math.min(Number(req.query.limit||100),500); const events=await prisma.motionEvent.findMany({where:{userId:req.userId!},include:{device:true,recording:true},orderBy:{detectedAt:'desc'},take:limit}); res.json(events);
});
app.delete('/api/events/:id',auth,async(req:AuthedRequest,res)=>{const e=await prisma.motionEvent.findFirst({where:{id:req.params.id,userId:req.userId!}});if(!e)return res.status(404).json({error:'Event not found'});await prisma.motionEvent.delete({where:{id:e.id}});res.json({ok:true});});
app.get('/api/recordings',auth,async(req:AuthedRequest,res)=>res.json(await prisma.recording.findMany({where:{userId:req.userId!},include:{device:true},orderBy:{createdAt:'desc'},take:200})));
app.post('/api/recordings',auth,upload.single('video'),async(req:AuthedRequest,res)=>{if(!req.file)return res.status(400).json({error:'Video file required'});const d=await prisma.device.findFirst({where:{id:req.body.deviceId,userId:req.userId!}});if(!d){fs.unlinkSync(req.file.path);return res.status(404).json({error:'Device not found'});}const r=await prisma.recording.create({data:{userId:req.userId!,deviceId:d.id,filePath:req.file.filename,mimeType:req.file.mimetype,durationSec:req.body.durationSec?Number(req.body.durationSec):null,fileSize:req.file.size}});res.status(201).json(r);});
app.get('/api/recordings/:id',auth,async(req:AuthedRequest,res)=>{const r=await prisma.recording.findFirst({where:{id:req.params.id,userId:req.userId!}});if(!r)return res.status(404).end();res.sendFile(path.join(uploadDir,r.filePath));});
app.delete('/api/recordings/:id',auth,async(req:AuthedRequest,res)=>{const r=await prisma.recording.findFirst({where:{id:req.params.id,userId:req.userId!}});if(!r)return res.status(404).json({error:'Recording not found'});try{fs.unlinkSync(path.join(uploadDir,r.filePath));}catch{}await prisma.recording.delete({where:{id:r.id}});res.json({ok:true});});

app.post('/api/push/subscribe',auth,async(req:AuthedRequest,res)=>{const s=req.body; if(!s?.endpoint||!s?.keys?.p256dh||!s?.keys?.auth)return res.status(400).json({error:'Invalid subscription'});await prisma.pushSubscription.upsert({where:{endpoint:s.endpoint},update:{p256dh:s.keys.p256dh,auth:s.keys.auth,userId:req.userId!},create:{endpoint:s.endpoint,p256dh:s.keys.p256dh,auth:s.keys.auth,userId:req.userId!}});res.json({ok:true});});
app.delete('/api/push/subscribe',auth,async(req:AuthedRequest,res)=>{await prisma.pushSubscription.deleteMany({where:{endpoint:req.body?.endpoint,userId:req.userId!}});res.json({ok:true});});
app.get('/api/push/public-key',auth,(_req,res)=>res.json({publicKey:process.env.VAPID_PUBLIC_KEY||null}));

app.get('/api/settings',auth,async(req:AuthedRequest,res)=>{const s=await prisma.userSettings.findUnique({where:{userId:req.userId!}});res.json(s);});
app.patch('/api/settings',auth,async(req:AuthedRequest,res)=>{const allowed=['motionSensitivity','alertCooldownSec','recordingDurationSec','alarmEnabled','alarmVolume','notificationsEnabled'];const data:any={};for(const k of allowed)if(req.body?.[k]!==undefined)data[k]=req.body[k];const s=await prisma.userSettings.upsert({where:{userId:req.userId!},create:{userId:req.userId!,...data},update:data});res.json(s);});

async function notifyMotion(userId:string, cameraName:string, eventId?:string){
  if(!process.env.VAPID_PUBLIC_KEY)return;
  const subs=await prisma.pushSubscription.findMany({where:{userId}});
  let delivered=false;
  for(const s of subs){try{await webpush.sendNotification({endpoint:s.endpoint,keys:{p256dh:s.p256dh,auth:s.auth}},JSON.stringify({title:'VK SECURITY',body:`MOTION DETECTED! Movement detected. Camera: ${cameraName}`,tag:`motion-${Date.now()}`})); delivered=true; }catch(e:any){if(e?.statusCode===404||e?.statusCode===410)await prisma.pushSubscription.delete({where:{id:s.id}});}}
  if(eventId) await prisma.motionEvent.update({where:{id:eventId},data:{notificationSent:delivered}}).catch(()=>{});
}

const wss=new WebSocketServer({server,path:'/ws'});
const sockets=new Map<string,Set<WebSocket>>();
function broadcastUser(userId:string,msg:any){for(const ws of sockets.get(userId)||[]){if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify(msg));}}
function getUserFromCookie(cookie:string|undefined){const m=cookie?.match(/(?:^|; )vk_session=([^;]+)/);if(!m)return null;try{return (jwt.verify(decodeURIComponent(m[1]),JWT_SECRET) as any).sub as string;}catch{return null;}}
wss.on('connection',(ws,req)=>{const userId=getUserFromCookie(req.headers.cookie);if(!userId){ws.close(1008,'Unauthorized');return;}if(!sockets.has(userId))sockets.set(userId,new Set());sockets.get(userId)!.add(ws);ws.send(JSON.stringify({type:'ready'}));
  ws.on('message',async raw=>{try{const msg=JSON.parse(raw.toString());
    if(['viewer-ready','offer','answer','ice'].includes(msg.type)){const p=await prisma.pairing.findFirst({where:{userId,status:'APPROVED',OR:[{cameraDeviceId:msg.fromDeviceId,viewerDeviceId:msg.toDeviceId},{cameraDeviceId:msg.toDeviceId,viewerDeviceId:msg.fromDeviceId}]}});if(!p)return;broadcastUser(userId,{...msg});return;}
    if(msg.type==='presence'){await prisma.device.updateMany({where:{id:msg.deviceId,userId},data:{isOnline:Boolean(msg.online),lastSeenAt:new Date(),cameraPermission:Boolean(msg.cameraPermission)}});broadcastUser(userId,{type:'presence',deviceId:msg.deviceId,online:Boolean(msg.online)});return;}
    if(msg.type==='motion'){const d=await prisma.device.findFirst({where:{id:msg.deviceId,userId}});if(!d)return;const settings=await prisma.userSettings.findUnique({where:{userId}});const recent=await prisma.motionEvent.findFirst({where:{userId,deviceId:d.id,detectedAt:{gt:new Date(Date.now()-((settings?.alertCooldownSec||30)*1000))}});if(recent)return;const ev=await prisma.motionEvent.create({data:{userId,deviceId:d.id}});broadcastUser(userId,{type:'motion',event:ev,deviceId:d.id});notifyMotion(userId,d.name,ev.id).catch(()=>{});return;}
  }catch{ /* malformed messages are ignored */ }});
  ws.on('close',()=>{sockets.get(userId)?.delete(ws);if(sockets.get(userId)?.size===0)sockets.delete(userId);});
});

setInterval(async()=>{await prisma.pairing.updateMany({where:{status:PairingStatus.PENDING,expiresAt:{lt:new Date()}},data:{status:PairingStatus.EXPIRED}});},60_000);

server.listen(PORT,()=>console.log(`VK SECURITY API listening on :${PORT}`));
