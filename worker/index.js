const json = (data, status=200, extra={}) => new Response(JSON.stringify(data), {
  status,
  headers: {"content-type":"application/json; charset=utf-8", ...extra}
});

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
};

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
}
function fromB64url(s) {
  s=s.replaceAll("-","+").replaceAll("_","/");
  while(s.length%4) s+="=";
  const raw=atob(s);
  return Uint8Array.from(raw,c=>c.charCodeAt(0));
}
function randomToken(n=32) {
  const b=new Uint8Array(n); crypto.getRandomValues(b); return b64url(b);
}
async function derive(password, salt) {
  const key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"},key,256);
  return new Uint8Array(bits);
}
async function hashPassword(password) {
  const salt=new Uint8Array(16); crypto.getRandomValues(salt);
  const hash=await derive(password,salt);
  return `pbkdf2$100000$${b64url(salt)}$${b64url(hash)}`;
}
async function verifyPassword(password, stored) {
  const [scheme,it,saltB,hashB]=String(stored).split("$");
  if(scheme!=="pbkdf2" || it!=="100000") return false;
  const got=await derive(password,fromB64url(saltB));
  const want=fromB64url(hashB);
  if(got.length!==want.length) return false;
  let diff=0; for(let i=0;i<got.length;i++) diff|=got[i]^want[i];
  return diff===0;
}
async function sign(value, secret) {
  const key=await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC",key,enc.encode(value))));
}
async function makeSession(userId, secret) {
  const payload=`${userId}.${Date.now()}`;
  return `${b64url(enc.encode(payload))}.${await sign(payload,secret)}`;
}
async function readSession(request, env) {
  const cookie=request.headers.get("Cookie")||"";
  const m=cookie.match(/(?:^|;\s*)pp_session=([^;]+)/);
  if(!m) return null;
  const parts=m[1].split(".");
  if(parts.length!==2) return null;
  const payload=dec.decode(fromB64url(parts[0]));
  const expected=await sign(payload,env.SESSION_SECRET);
  if(expected!==parts[1]) return null;
  const [id,created]=payload.split(".");
  if(!/^\d+$/.test(id)||!/^\d+$/.test(created)) return null;
  if(Date.now()-Number(created)>1000*60*60*24*7) return null;
  return Number(id);
}
function cookie(value,maxAge=604800) {
  return `pp_session=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}
function normalizeEmail(v){return String(v||"").trim().toLowerCase();}
function validName(v){return /^[\p{L}\p{N} ._'-]{2,60}$/u.test(String(v||"").trim());}
function validPassword(v){return typeof v==="string" && v.length>=8 && v.length<=128;}
function validReferral(v){return !v || /^[A-Z0-9]{6,20}$/.test(String(v).trim().toUpperCase());}
function makeReferral(){return randomToken(8).toUpperCase().replace(/[^A-Z0-9]/g,"").slice(0,10);}

async function api(request, env) {
  const url=new URL(request.url);
  if(url.pathname==="/api/health") return json({ok:true,service:"pitbull-prime"},200,cors);

  if(request.method==="OPTIONS") return new Response(null,{status:204,headers:cors});

  if(!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);

  try {
    if(!env.DB) return json({ok:false,error:"Banco D1 não configurado."},500,cors);
    if(!env.SESSION_SECRET) return json({ok:false,error:"SESSION_SECRET não configurado."},500,cors);
    async function sha256Hex(value){
      const data=new TextEncoder().encode(String(value||""));
      const digest=await crypto.subtle.digest("SHA-256",data);
      return Array.from(new Uint8Array(digest)).map(b=>b.toString(16).padStart(2,"0")).join("");
    }

    async function referralRisk(env, referrerId, newUserId, request){
      if((await platformSetting("referral_risk_enabled","1"))!=="1") return {level:"low",reason:null};
      const ip=request.headers.get("CF-Connecting-IP")||request.headers.get("X-Forwarded-For")||"unknown";
      const ua=request.headers.get("User-Agent")||"unknown";
      const ipHash=await sha256Hex(ip);
      const uaHash=await sha256Hex(ua);
      await env.DB.prepare(`
        INSERT OR REPLACE INTO referral_security(user_id,ip_hash,ua_hash,risk_level,risk_reason)
        VALUES(?,?,?,?,?)
      `).bind(newUserId,ipHash,uaHash,"low",null).run();

      const ipLimit=Math.max(1,Number(await platformSetting("referral_ip_limit","3")));
      const uaLimit=Math.max(1,Number(await platformSetting("referral_ua_limit","5")));
      const sameIp=await env.DB.prepare(`
        SELECT COUNT(*) c FROM referral_security WHERE ip_hash=? AND user_id!=?
      `).bind(ipHash,newUserId).first();
      const sameUa=await env.DB.prepare(`
        SELECT COUNT(*) c FROM referral_security WHERE ua_hash=? AND user_id!=?
      `).bind(uaHash,newUserId).first();
      const refSec=await env.DB.prepare("SELECT ip_hash,ua_hash FROM referral_security WHERE user_id=?").bind(referrerId).first();

      if(refSec?.ip_hash===ipHash){
        return {level:"high",reason:"O indicador e o indicado utilizaram o mesmo endereço de rede identificado pela hospedagem."};
      }
      if(Number(sameIp?.c||0)>=ipLimit){
        return {level:"high",reason:`O endereço de rede já foi associado a ${sameIp.c} outros cadastros.`};
      }
      if(refSec?.ua_hash===uaHash){
        return {level:"medium",reason:"O indicador e o indicado apresentam o mesmo identificador de navegador."};
      }
      if(Number(sameUa?.c||0)>=uaLimit){
        return {level:"medium",reason:`O mesmo navegador já aparece em ${sameUa.c} outros cadastros.`};
      }
      return {level:"low",reason:null};
    }



    if(url.pathname==="/api/register" && request.method==="POST") {
      const body=await request.json();
      const name=String(body.name||"").trim();
      const email=normalizeEmail(body.email);
      const password=body.password;
      const ref=String(body.referral||"").trim().toUpperCase();

      if(!validName(name)) return json({ok:false,error:"Nome inválido."},400,cors);
      if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ok:false,error:"E-mail inválido."},400,cors);
      if(!validPassword(password)) return json({ok:false,error:"A senha deve ter pelo menos 8 caracteres."},400,cors);
      if(!validReferral(ref)) return json({ok:false,error:"Código de indicação inválido."},400,cors);

      const existing=await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first();
      if(existing) return json({ok:false,error:"Este e-mail já está cadastrado."},409,cors);

      let referrer=null;
      if(ref) {
        referrer=await env.DB.prepare("SELECT id FROM users WHERE referral_code=? AND status='active'").bind(ref).first();
        if(!referrer) return json({ok:false,error:"Código de indicação não encontrado."},400,cors);
      }

      let code=makeReferral();
      for(let i=0;i<5;i++){
        const exists=await env.DB.prepare("SELECT id FROM users WHERE referral_code=?").bind(code).first();
        if(!exists) break;
        code=makeReferral();
      }

      const passwordHash=await hashPassword(password);
      const result=await env.DB.prepare(
        "INSERT INTO users(name,email,password_hash,referral_code,referred_by) VALUES(?,?,?,?,?)"
      ).bind(name,email,passwordHash,code,referrer?.id||null).run();

      const userId=result.meta.last_row_id;

      const ip=request.headers.get("CF-Connecting-IP")||request.headers.get("X-Forwarded-For")||"unknown";
      const ua=request.headers.get("User-Agent")||"unknown";
      await env.DB.prepare(
        "INSERT OR REPLACE INTO referral_security(user_id,ip_hash,ua_hash,risk_level,risk_reason) VALUES(?,?,?,?,?)"
      ).bind(userId,await sha256Hex(ip),await sha256Hex(ua),"low",null).run();

      if(referrer) {
        const risk=await referralRisk(env,referrer.id,userId,request);
        const event=await env.DB.prepare(
          "INSERT INTO referral_events(referrer_id,referred_user_id,status,reason) VALUES(?,?,?,?)"
        ).bind(referrer.id,userId,"pending",risk.reason).run();

        if(risk.level!=="low"){
          await env.DB.prepare(
            "UPDATE referral_security SET risk_level=?,risk_reason=? WHERE user_id=?"
          ).bind(risk.level,risk.reason,userId).run();

          await env.DB.prepare(
            "INSERT INTO referral_risk_events(referral_id,referrer_id,referred_user_id,risk_level,reason) VALUES(?,?,?,?,?)"
          ).bind(event.meta.last_row_id,referrer.id,userId,risk.level,risk.reason).run();
        }
      }

      const session=await makeSession(userId,env.SESSION_SECRET);
      await env.DB.prepare(
        "INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)"
      ).bind(userId,"register",userId,referrer?`ref=${ref}`:null).run();

      return json({ok:true,user:{id:userId,name,email,plan:"FREE"}},200,{
        ...cors,"Set-Cookie":cookie(session)
      });
    }

    if(url.pathname==="/api/login" && request.method==="POST") {
      const body=await request.json();
      const email=normalizeEmail(body.email);
      const password=body.password;
      const user=await env.DB.prepare(
        "SELECT id,name,email,password_hash,plan,vip_until,status FROM users WHERE email=?"
      ).bind(email).first();

      if(!user || !(await verifyPassword(password,user.password_hash)))
        return json({ok:false,error:"E-mail ou senha incorretos."},401,cors);
      if(user.status==="banned")
        return json({ok:false,error:"Esta conta está bloqueada."},403,cors);

      const session=await makeSession(user.id,env.SESSION_SECRET);
      await env.DB.prepare("UPDATE users SET updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(user.id).run();

      return json({ok:true,user:{id:user.id,name:user.name,email:user.email,plan:user.plan,vip_until:user.vip_until}},200,{
        ...cors,"Set-Cookie":cookie(session)
      });
    }

    if(url.pathname==="/api/logout" && request.method==="POST")
      return json({ok:true},200,{...cors,"Set-Cookie":cookie("",0)});



    async function requireAdmin() {
      const id=await readSession(request,env);
      if(!id) return {error:json({ok:false,error:"Não autenticado."},401,cors)};
      if(Number(env.ADMIN_USER_ID||0)!==id) return {error:json({ok:false,error:"Acesso negado."},403,cors)};
      return {id};
    }

    if(url.pathname==="/api/admin/stats" && request.method==="GET") {
      const auth=await requireAdmin(); if(auth.error)return auth.error;
      const [users,vip,banned,pending,balances]=await Promise.all([
        env.DB.prepare("SELECT COUNT(*) c FROM users").first(),
        env.DB.prepare("SELECT COUNT(*) c FROM users WHERE plan='VIP' AND vip_until>CURRENT_TIMESTAMP AND status='active'").first(),
        env.DB.prepare("SELECT COUNT(*) c FROM users WHERE status='banned'").first(),
        env.DB.prepare("SELECT COUNT(*) c FROM referral_events WHERE status='pending'").first(),
        env.DB.prepare("SELECT COALESCE(SUM(balance_cents),0) c FROM users WHERE status='active'").first()
      ]);
      return json({ok:true,stats:{
        users:Number(users?.c||0),vip:Number(vip?.c||0),banned:Number(banned?.c||0),
        pending_referrals:Number(pending?.c||0),total_balance_cents:Number(balances?.c||0)
      }},200,cors);
    }

    if(url.pathname==="/api/admin/users" && request.method==="GET") {
      const auth=await requireAdmin(); if(auth.error)return auth.error;
      const q=String(url.searchParams.get("q")||"").trim().slice(0,80);
      const limit=Math.min(100,Math.max(1,Number(url.searchParams.get("limit")||50)));
      let result;
      if(q) {
        const like=`%${q}%`;
        result=await env.DB.prepare(`
          SELECT id,name,email,referral_code,plan,vip_until,balance_cents,coins,gems,xp,status,created_at
          FROM users WHERE name LIKE ? OR email LIKE ? OR referral_code LIKE ? OR CAST(id AS TEXT)=?
          ORDER BY id DESC LIMIT ?`).bind(like,like,like,q,limit).all();
      } else {
        result=await env.DB.prepare(`
          SELECT id,name,email,referral_code,plan,vip_until,balance_cents,coins,gems,xp,status,created_at
          FROM users ORDER BY id DESC LIMIT ?`).bind(limit).all();
      }
      return json({ok:true,users:result.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/user/update" && request.method==="POST") {
      const auth=await requireAdmin(); if(auth.error)return auth.error;
      const body=await request.json();
      const target=Number(body.user_id);
      const action=String(body.action||"").toLowerCase();
      const reason=String(body.reason||"").trim().slice(0,500);
      if(!Number.isInteger(target)||target<=0) return json({ok:false,error:"Usuário inválido."},400,cors);
      if(target===auth.id && ["ban","unban"].includes(action)) return json({ok:false,error:"Não é permitido bloquear/desbloquear o próprio administrador."},400,cors);

      const user=await env.DB.prepare("SELECT id,status,balance_cents FROM users WHERE id=?").bind(target).first();
      if(!user) return json({ok:false,error:"Usuário não encontrado."},404,cors);

      if(action==="ban"||action==="unban"){
        const status=action==="ban"?"banned":"active";
        await env.DB.batch([
          env.DB.prepare("UPDATE users SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(status,target),
          env.DB.prepare("INSERT INTO admin_actions(admin_user_id,action,target_user_id,reason) VALUES(?,?,?,?)").bind(auth.id,action,target,reason||null),
          env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)").bind(auth.id,action,target,reason||null)
        ]);
        return json({ok:true,message:status==="banned"?"Usuário bloqueado.":"Usuário desbloqueado."},200,cors);
      }

      if(action==="add_balance"){
        const amount=Number(body.amount_cents);
        if(!Number.isInteger(amount)||amount<=0||amount>100000000) return json({ok:false,error:"Valor inválido."},400,cors);
        await env.DB.batch([
          env.DB.prepare("UPDATE users SET balance_cents=balance_cents+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(amount,target),
          env.DB.prepare("INSERT INTO admin_actions(admin_user_id,action,target_user_id,amount_cents,reason) VALUES(?,?,?,?,?)").bind(auth.id,action,target,amount,reason||null),
          env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)").bind(auth.id,action,target,JSON.stringify({amount_cents:amount,reason:reason||null}))
        ]);
        return json({ok:true,message:"Saldo adicionado.",new_balance_cents:Number(user.balance_cents||0)+amount},200,cors);
      }

      return json({ok:false,error:"Ação não reconhecida."},400,cors);
    }


    if(url.pathname==="/api/referrals/summary" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const user=await env.DB.prepare("SELECT id,referral_code FROM users WHERE id=? AND status='active'").bind(id).first();
      if(!user)return json({ok:false,error:"Usuário não encontrado."},404,cors);
      const stats=await env.DB.prepare(`
        SELECT
          COUNT(*) total,
          SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) approved,
          SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) pending,
          SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) rejected,
          COALESCE(SUM(CASE WHEN status='approved' THEN reward_cents ELSE 0 END),0) earned_cents
        FROM referral_events WHERE referrer_id=?`).bind(id).first();
      const risk=await env.DB.prepare(`
        SELECT COUNT(*) c FROM referral_risk_events WHERE referrer_id=? AND risk_level!='low'
      `).bind(id).first();
      return json({ok:true,referral_code:user.referral_code,
        referral_link:`${url.origin}/cadastro.html?ref=${encodeURIComponent(user.referral_code)}`,
        stats:{total:Number(stats?.total||0),approved:Number(stats?.approved||0),
          pending:Number(stats?.pending||0),rejected:Number(stats?.rejected||0),
          earned_cents:Number(stats?.earned_cents||0),risk_flags:Number(risk?.c||0)}
      },200,cors);
    }

    if(url.pathname==="/api/referrals" && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      const user=await env.DB.prepare("SELECT id,referral_code FROM users WHERE id=? AND status='active'").bind(id).first();
      if(!user) return json({ok:false,error:"Usuário não encontrado."},404,cors);

      const totals=await env.DB.prepare(`
        SELECT COUNT(*) total,
        SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) approved,
        SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) pending,
        SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) rejected,
        COALESCE(SUM(CASE WHEN status='approved' THEN reward_cents ELSE 0 END),0) earned_cents
        FROM referral_events WHERE referrer_id=?`).bind(id).first();

      const rows=await env.DB.prepare(`
        SELECT r.id,r.status,r.reward_cents,r.reason,r.created_at,r.approved_at,
               u.name referred_name
        FROM referral_events r JOIN users u ON u.id=r.referred_user_id
        WHERE r.referrer_id=? ORDER BY r.id DESC LIMIT 100`).bind(id).all();

      return json({
        ok:true,
        referral_code:user.referral_code,
        referral_link:`${url.origin}/cadastro.html?ref=${encodeURIComponent(user.referral_code)}`,
        totals:{
          total:Number(totals?.total||0), approved:Number(totals?.approved||0),
          pending:Number(totals?.pending||0), rejected:Number(totals?.rejected||0),
          earned_cents:Number(totals?.earned_cents||0)
        },
        referrals:rows.results||[]
      },200,cors);
    }


    if(url.pathname==="/api/admin/referral-risks" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const rows=await env.DB.prepare(`
        SELECT rr.id,rr.referral_id,rr.risk_level,rr.reason,rr.created_at,
               ref.name referrer_name,ind.name referred_name
        FROM referral_risk_events rr
        JOIN users ref ON ref.id=rr.referrer_id
        JOIN users ind ON ind.id=rr.referred_user_id
        ORDER BY CASE rr.risk_level WHEN 'high' THEN 0 ELSE 1 END,rr.id DESC LIMIT 200
      `).all();
      return json({ok:true,risks:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/referrals" && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id) return json({ok:false,error:"Acesso negado."},403,cors);
      const rows=await env.DB.prepare(`
        SELECT r.id,r.status,r.reward_cents,r.reason,r.created_at,
               ref.name referrer_name,ref.email referrer_email,
               ind.name referred_name,ind.email referred_email
        FROM referral_events r
        JOIN users ref ON ref.id=r.referrer_id
        JOIN users ind ON ind.id=r.referred_user_id
        ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END,r.id DESC LIMIT 200`).all();
      return json({ok:true,referrals:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/referrals/process" && request.method==="POST") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id) return json({ok:false,error:"Acesso negado."},403,cors);

      const body=await request.json();
      const referralId=Number(body.referral_id);
      const action=String(body.action||"").toLowerCase();
      const reason=String(body.reason||"").trim().slice(0,500);
      if(!Number.isInteger(referralId)||!["approve","reject"].includes(action))
        return json({ok:false,error:"Dados inválidos."},400,cors);

      const r=await env.DB.prepare("SELECT * FROM referral_events WHERE id=?").bind(referralId).first();
      if(!r) return json({ok:false,error:"Indicação não encontrada."},404,cors);
      if(r.status!=="pending") return json({ok:false,error:"Essa indicação já foi processada."},409,cors);

      const reward=Number((await env.DB.prepare(
        "SELECT value FROM settings WHERE key='referral_reward_cents'").first())?.value||0);

      if(action==="approve"){
        const amount=Math.max(0,Math.floor(reward));
        await env.DB.batch([
          env.DB.prepare("UPDATE referral_events SET status='approved',reward_cents=?,approved_at=CURRENT_TIMESTAMP WHERE id=?").bind(amount,referralId),
          env.DB.prepare("UPDATE users SET balance_cents=balance_cents+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(amount,r.referrer_id),
          env.DB.prepare("INSERT INTO referral_rewards(referral_id,referrer_id,referred_user_id,reward_cents,status,reason,processed_at) VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP)").bind(referralId,r.referrer_id,r.referred_user_id,amount,"approved",reason||null),
          env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)").bind(id,"approve_referral",r.referrer_id,JSON.stringify({referral_id:referralId,reward_cents:amount}))
        ]);
        return json({ok:true,message:"Indicação aprovada.",reward_cents:amount},200,cors);
      }

      await env.DB.batch([
        env.DB.prepare("UPDATE referral_events SET status='rejected',reason=? WHERE id=?").bind(reason||"Rejeitada pela administração.",referralId),
        env.DB.prepare("INSERT INTO referral_rewards(referral_id,referrer_id,referred_user_id,reward_cents,status,reason,processed_at) VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP)").bind(referralId,r.referrer_id,r.referred_user_id,0,"rejected",reason||"Rejeitada pela administração.")
      ]);
      return json({ok:true,message:"Indicação rejeitada."},200,cors);
    }


    if(await maintenanceGuard()) return await maintenanceGuard();
    if(url.pathname==="/api/games/status" && request.method==="GET") {
      if((await platformSetting("games_enabled","1"))!=="1") return json({ok:false,error:"Os jogos estão temporariamente desativados."},503,cors);
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      const user=await env.DB.prepare("SELECT id,plan,status FROM users WHERE id=?").bind(id).first();
      if(!user||user.status!=="active") return json({ok:false,error:"Conta indisponível."},403,cors);
      const rows=await env.DB.prepare(`
        SELECT game, COUNT(*) plays
        FROM game_plays
        WHERE user_id=? AND created_at>=datetime('now','start of day')
        GROUP BY game`).bind(id).all();
      const used={roulette:0,scratch:0};
      for(const r of (rows.results||[])) used[r.game]=Number(r.plays||0);
      const limits={roulette:user.plan==="VIP"?2:1,scratch:user.plan==="VIP"?2:1};
      return json({ok:true,plan:user.plan,used,limits,remaining:{
        roulette:Math.max(0,limits.roulette-used.roulette),
        scratch:Math.max(0,limits.scratch-used.scratch)
      }},200,cors);
    }

    async function playGame(game){
      if((await platformSetting("games_enabled","1"))!=="1") return json({ok:false,error:"Os jogos estão temporariamente desativados."},503,cors);
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      if(!["roulette","scratch"].includes(game)) return json({ok:false,error:"Jogo inválido."},400,cors);

      const user=await env.DB.prepare("SELECT id,plan,status FROM users WHERE id=?").bind(id).first();
      if(!user||user.status!=="active") return json({ok:false,error:"Conta indisponível."},403,cors);

      const limit=user.plan==="VIP"?2:1;
      const count=await env.DB.prepare(`
        SELECT COUNT(*) c FROM game_plays
        WHERE user_id=? AND game=? AND created_at>=datetime('now','start of day')`
      ).bind(id,game).first();
      if(Number(count?.c||0)>=limit)
        return json({ok:false,error:`Você já usou seus ${limit} ${game==="roulette"?"giros":"jogos"} de hoje.`},429,cors);

      const prizes=await env.DB.prepare(`
        SELECT id,label,reward_type,reward_value,weight
        FROM game_prizes WHERE game=? AND enabled=1 AND weight>0
        ORDER BY id`).bind(game).all();
      const list=prizes.results||[];
      if(!list.length) return json({ok:false,error:"Jogo temporariamente indisponível."},503,cors);

      const total=list.reduce((a,p)=>a+Number(p.weight||0),0);
      const rnd=new Uint32Array(1); crypto.getRandomValues(rnd);
      let pick=(rnd[0]/4294967296)*total, prize=list[list.length-1];
      for(const p of list){pick-=Number(p.weight||0);if(pick<0){prize=p;break;}}

      const amount=Math.max(0,Math.floor(Number(prize.reward_value||0)));
      const stmts=[
        env.DB.prepare("INSERT INTO game_plays(user_id,game,prize_id,reward_type,reward_value) VALUES(?,?,?,?,?)")
          .bind(id,game,prize.id,prize.reward_type,amount)
      ];
      if(prize.reward_type==="balance" && amount>0)
        stmts.push(env.DB.prepare("UPDATE users SET balance_cents=balance_cents+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(amount,id));
      if(prize.reward_type==="coins" && amount>0)
        stmts.push(env.DB.prepare("UPDATE users SET coins=coins+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(amount,id));
      if(prize.reward_type==="gems" && amount>0)
        stmts.push(env.DB.prepare("UPDATE users SET gems=gems+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(amount,id));
      await env.DB.batch(stmts);

      return json({ok:true,game,prize:{
        label:prize.label,type:prize.reward_type,value:amount
      }},200,cors);
    }

    if(await maintenanceGuard()) return await maintenanceGuard();
    if(url.pathname==="/api/games/roulette" && request.method==="POST")
      return await playGame("roulette");

    if(await maintenanceGuard()) return await maintenanceGuard();
    if(url.pathname==="/api/games/scratch" && request.method==="POST")
      return await playGame("scratch");

    if(url.pathname==="/api/admin/games/prizes" && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id) return json({ok:false,error:"Acesso negado."},403,cors);
      const rows=await env.DB.prepare("SELECT * FROM game_prizes ORDER BY game,id").all();
      return json({ok:true,prizes:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/games/prize" && request.method==="POST") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id) return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json();
      const prizeId=Number(b.id);
      const label=String(b.label||"").trim().slice(0,80);
      const weight=Math.max(0,Math.floor(Number(b.weight||0)));
      const enabled=b.enabled?1:0;
      const value=Math.max(0,Math.floor(Number(b.reward_value||0)));
      if(!Number.isInteger(prizeId)||!label||!Number.isInteger(weight)||!Number.isInteger(value))
        return json({ok:false,error:"Dados inválidos."},400,cors);
      const prize=await env.DB.prepare("SELECT * FROM game_prizes WHERE id=?").bind(prizeId).first();
      if(!prize) return json({ok:false,error:"Prêmio não encontrado."},404,cors);
      await env.DB.prepare("UPDATE game_prizes SET label=?,reward_value=?,weight=?,enabled=? WHERE id=?")
        .bind(label,value,weight,enabled,prizeId).run();
      await env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)")
        .bind(id,"update_game_prize",id,JSON.stringify({prize_id:prizeId,label,weight,value,enabled})).run();
      return json({ok:true,message:"Prêmio atualizado."},200,cors);
    }


    if(url.pathname==="/api/vip" && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      const user=await env.DB.prepare(
        "SELECT id,plan,vip_until FROM users WHERE id=? AND status='active'"
      ).bind(id).first();
      if(!user) return json({ok:false,error:"Conta indisponível."},403,cors);
      const price=await env.DB.prepare("SELECT value FROM settings WHERE key='vip_price_cents'").first();
      const duration=await env.DB.prepare("SELECT value FROM settings WHERE key='vip_duration_days'").first();
      return json({
        ok:true,
        plan:user.plan,
        vip_until:user.vip_until,
        price_cents:Number(price?.value||999),
        duration_days:Number(duration?.value||30),
        benefits:[
          "2 giros de roleta por dia",
          "2 raspadinhas por dia",
          "Mais benefícios e chances conforme as regras da plataforma",
          "Acesso aos recursos VIP enquanto a assinatura estiver ativa"
        ],
        purchase_method:"support"
      },200,cors);
    }

    if(url.pathname==="/api/vip/redeem" && request.method==="POST") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      const body=await request.json();
      const code=String(body.code||"").trim().toUpperCase();
      if(!/^[A-Z0-9-]{4,40}$/.test(code))
        return json({ok:false,error:"Código inválido."},400,cors);

      const promo=await env.DB.prepare(
        "SELECT * FROM promo_codes WHERE code=? AND enabled=1"
      ).bind(code).first();
      if(!promo) return json({ok:false,error:"Código não encontrado ou desativado."},404,cors);
      if(promo.expires_at && String(promo.expires_at)<new Date().toISOString())
        return json({ok:false,error:"Esse código expirou."},409,cors);
      if(Number(promo.redemptions)>=Number(promo.max_redemptions))
        return json({ok:false,error:"Esse código já atingiu o limite de resgates."},409,cors);

      const already=await env.DB.prepare(
        "SELECT id FROM promo_redemptions WHERE promo_id=? AND user_id=?"
      ).bind(promo.id,id).first();
      if(already) return json({ok:false,error:"Você já resgatou esse código."},409,cors);

      const user=await env.DB.prepare("SELECT plan,vip_until,status FROM users WHERE id=?").bind(id).first();
      if(!user||user.status!=="active") return json({ok:false,error:"Conta indisponível."},403,cors);

      const now=new Date();
      const currentVip=user.vip_until && String(user.vip_until)>now.toISOString()
        ? new Date(user.vip_until) : now;
      currentVip.setUTCDate(currentVip.getUTCDate()+Number(promo.duration_days));
      const until=currentVip.toISOString();

      await env.DB.batch([
        env.DB.prepare("UPDATE users SET plan='VIP',vip_until=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(until,id),
        env.DB.prepare("UPDATE promo_codes SET redemptions=redemptions+1 WHERE id=?").bind(promo.id),
        env.DB.prepare("INSERT INTO promo_redemptions(promo_id,user_id) VALUES(?,?)").bind(promo.id,id),
        env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)").bind(id,"redeem_vip_code",id,JSON.stringify({promo_id:promo.id,duration_days:promo.duration_days}))
      ]);
      await createNotification(env,id,"vip","💎 VIP ativado",`Seu VIP foi ativado até ${new Date(until).toLocaleDateString("pt-BR")}.`);
      return json({ok:true,message:"VIP ativado com sucesso.",vip_until:until},200,cors);
    }

    if(url.pathname==="/api/admin/vip/settings" && request.method==="POST") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id) return json({ok:false,error:"Acesso negado."},403,cors);
      const body=await request.json();
      const price=Number(body.price_cents);
      const days=Number(body.duration_days);
      if(!Number.isInteger(price)||price<0||price>100000000||!Number.isInteger(days)||days<1||days>3650)
        return json({ok:false,error:"Configuração VIP inválida."},400,cors);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO settings(key,value,updated_at) VALUES('vip_price_cents',?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP").bind(String(price)),
        env.DB.prepare("INSERT INTO settings(key,value,updated_at) VALUES('vip_duration_days',?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP").bind(String(days)),
        env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)").bind(id,"update_vip_settings",id,JSON.stringify({price_cents:price,duration_days:days}))
      ]);
      return json({ok:true,message:"Configuração VIP atualizada."},200,cors);
    }

    if(url.pathname==="/api/admin/vip/codes" && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id) return json({ok:false,error:"Acesso negado."},403,cors);
      const rows=await env.DB.prepare(`
        SELECT id,code,duration_days,max_redemptions,redemptions,enabled,created_at,expires_at
        FROM promo_codes ORDER BY id DESC LIMIT 200`).all();
      return json({ok:true,codes:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/vip/codes" && request.method==="POST") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id) return json({ok:false,error:"Acesso negado."},403,cors);
      const body=await request.json();
      const duration=Number(body.duration_days);
      const max=Number(body.max_redemptions);
      const qty=Math.min(1000,Math.max(1,Number(body.quantity||1)));
      if(!Number.isInteger(duration)||duration<1||duration>3650||!Number.isInteger(max)||max<1||max>100000)
        return json({ok:false,error:"Duração ou quantidade de resgates inválida."},400,cors);

      const created=[];
      for(let i=0;i<qty;i++){
        let code;
        for(let tries=0;tries<10;tries++){
          const b=new Uint8Array(8);crypto.getRandomValues(b);
          code="VIP-"+Array.from(b).map(x=>x.toString(16).padStart(2,"0")).join("").slice(0,12).toUpperCase();
          const exists=await env.DB.prepare("SELECT id FROM promo_codes WHERE code=?").bind(code).first();
          if(!exists)break;
        }
        await env.DB.prepare(
          "INSERT INTO promo_codes(code,duration_days,max_redemptions,created_by) VALUES(?,?,?,?)"
        ).bind(code,duration,max,id).run();
        created.push(code);
      }
      await env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)")
        .bind(id,"create_vip_codes",id,JSON.stringify({quantity:qty,duration_days:duration,max_redemptions:max})).run();
      return json({ok:true,codes:created},200,cors);
    }

    if(url.pathname==="/api/admin/vip/code/toggle" && request.method==="POST") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id) return json({ok:false,error:"Acesso negado."},403,cors);
      const body=await request.json(); const codeId=Number(body.id);
      if(!Number.isInteger(codeId)) return json({ok:false,error:"Código inválido."},400,cors);
      const row=await env.DB.prepare("SELECT enabled FROM promo_codes WHERE id=?").bind(codeId).first();
      if(!row) return json({ok:false,error:"Código não encontrado."},404,cors);
      const next=row.enabled?0:1;
      await env.DB.prepare("UPDATE promo_codes SET enabled=? WHERE id=?").bind(next,codeId).run();
      await env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)").bind(id,"toggle_vip_code",id,JSON.stringify({code_id:codeId,enabled:next})).run();
      return json({ok:true,enabled:next},200,cors);
    }



    async function walletSummary(env,userId){
      const user=await env.DB.prepare(`
        SELECT balance_cents,status FROM users WHERE id=?
      `).bind(userId).first();
      const pending=await env.DB.prepare(`
        SELECT COALESCE(SUM(amount_cents),0) amount
        FROM withdrawal_requests WHERE user_id=? AND status='pending'
      `).bind(userId).first();
      const totals=await env.DB.prepare(`
        SELECT
          COALESCE(SUM(CASE WHEN type IN ('credit','game_reward','referral_reward','admin_credit','withdrawal_refund') THEN amount_cents ELSE 0 END),0) credits,
          COALESCE(SUM(CASE WHEN type IN ('debit','admin_debit') THEN amount_cents ELSE 0 END),0) debits,
          COALESCE(SUM(CASE WHEN type='withdrawal_hold' THEN amount_cents ELSE 0 END),0) holds
        FROM wallet_transactions WHERE user_id=?
      `).bind(userId).first();
      return {
        balance_cents:Number(user?.balance_cents||0),
        pending_withdrawal_cents:Number(pending?.amount||0),
        ledger_credits_cents:Number(totals?.credits||0),
        ledger_debits_cents:Number(totals?.debits||0),
        ledger_holds_cents:Number(totals?.holds||0),
        status:user?.status||"unknown"
      };
    }

    if(url.pathname==="/api/wallet/summary" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const summary=await walletSummary(env,id);
      if(summary.status!=="active")return json({ok:false,error:"Conta indisponível."},403,cors);
      return json({ok:true,...summary},200,cors);
    }

    if(url.pathname==="/api/wallet/statement" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const limit=Math.min(200,Math.max(1,Number(url.searchParams.get("limit")||100)));
      const rows=await env.DB.prepare(`
        SELECT id,type,amount_cents,reference_id,description,created_at
        FROM wallet_transactions WHERE user_id=? ORDER BY id DESC LIMIT ?
      `).bind(id,limit).all();
      return json({ok:true,transactions:rows.results||[]},200,cors);
    }

    
    if(url.pathname==="/api/admin/withdrawals" && request.method==="GET"){
      const adminId=await readSession(request,env);
      if(!adminId)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==adminId)return json({ok:false,error:"Acesso negado."},403,cors);
      const rows=await env.DB.prepare(`
        SELECT w.*,u.name,u.pix_key
        FROM withdrawal_requests w JOIN users u ON u.id=w.user_id
        ORDER BY CASE WHEN w.status='pending' THEN 0 ELSE 1 END,w.id DESC LIMIT 100
      `).all();
      return json({ok:true,withdrawals:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/withdrawals/action" && request.method==="POST"){
      const adminId=await readSession(request,env);
      if(!adminId)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==adminId)return json({ok:false,error:"Acesso negado."},403,cors);

      const b=await request.json().catch(()=>({}));
      const withdrawalId=Math.floor(Number(b.withdrawal_id));
      const action=["approved","rejected","cancelled"].includes(String(b.action))?String(b.action):"";
      const note=String(b.note||"").trim().slice(0,300);
      if(!Number.isInteger(withdrawalId)||withdrawalId<1||!action)
        return json({ok:false,error:"Dados do saque inválidos."},400,cors);

      const row=await env.DB.prepare(`
        SELECT * FROM withdrawal_requests WHERE id=?
      `).bind(withdrawalId).first();
      if(!row)return json({ok:false,error:"Saque não encontrado."},404,cors);
      if(row.status!=="pending")
        return json({ok:false,error:"Este saque já foi processado."},409,cors);

      // The audit UNIQUE(withdrawal_id,action) plus status check makes retries idempotent.
      try{
        if(action==="approved"){
          await env.DB.prepare(`
            UPDATE withdrawal_requests SET status='approved',updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'
          `).bind(withdrawalId).run();
          await env.DB.prepare(`
            UPDATE wallet_transactions SET description=? WHERE reference_id=? AND type='withdrawal_hold'
          `).bind("Saque aprovado e valor debitado",String(withdrawalId)).run();
        }else{
          await env.DB.prepare(`
            UPDATE withdrawal_requests SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'
          `).bind(action,withdrawalId).run();
          await env.DB.prepare(`
            UPDATE users SET balance_cents=balance_cents+?,updated_at=CURRENT_TIMESTAMP WHERE id=?
          `).bind(Number(row.amount_cents),Number(row.user_id)).run();
          await env.DB.prepare(`
            INSERT INTO wallet_transactions(user_id,type,amount_cents,reference_id,description)
            VALUES(?,'withdrawal_refund',?,?,?)
          `).bind(Number(row.user_id),Number(row.amount_cents),String(withdrawalId),action==="rejected"?"Saque rejeitado — valor devolvido":"Saque cancelado — valor devolvido").run();
        }

        await env.DB.prepare(`
          INSERT INTO withdrawal_audit(withdrawal_id,actor_user_id,action,amount_cents,note)
          VALUES(?,?,?,?,?)
        `).bind(withdrawalId,adminId,action,Number(row.amount_cents),note||null).run();

        await env.DB.prepare(`
          INSERT INTO audit_logs(actor_user_id,action,target_user_id,details)
          VALUES(?,?,?,?)
        `).bind(adminId,"withdrawal_"+action,Number(row.user_id),JSON.stringify({withdrawal_id:withdrawalId,amount_cents:Number(row.amount_cents),note})).run();

        await createNotification(env,Number(row.user_id),"withdrawal",
          action==="approved"?"✅ Saque aprovado":action==="rejected"?"❌ Saque rejeitado":"↩️ Saque cancelado",
          action==="approved"?"Seu saque foi aprovado e encaminhado para pagamento.":"O valor do saque foi devolvido à sua carteira.",{withdrawal_id:withdrawalId});

        return json({ok:true,message:"Saque processado com sucesso."},200,cors);
      }catch(e){
        console.error("WITHDRAW_ACTION_ERROR",String(e));
        return json({ok:false,error:"Não foi possível processar o saque."},500,cors);
      }
    }

if(url.pathname==="/api/admin/wallet/adjust" && request.method==="POST"){
      const adminId=await readSession(request,env);
      if(!adminId)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==adminId)return json({ok:false,error:"Acesso negado."},403,cors);

      const b=await request.json().catch(()=>({}));
      const userId=Math.floor(Number(b.user_id));
      const amount=Math.floor(Number(b.amount_cents));
      const type=["credit","debit"].includes(String(b.type))?String(b.type):"credit";
      const reason=String(b.reason||"").trim().slice(0,300);

      if(!Number.isInteger(userId)||userId<1||!Number.isInteger(amount)||amount<1||amount>100000000||reason.length<3)
        return json({ok:false,error:"Dados da alteração financeira inválidos."},400,cors);

      const user=await env.DB.prepare(`
        SELECT balance_cents,status FROM users WHERE id=?
      `).bind(userId).first();
      if(!user||user.status!=="active")return json({ok:false,error:"Usuário não encontrado ou indisponível."},404,cors);
      if(type==="debit" && Number(user.balance_cents)<amount)
        return json({ok:false,error:"Saldo insuficiente para o débito administrativo."},409,cors);

      const txType=type==="credit"?"admin_credit":"admin_debit";
      const result=await env.DB.prepare(`
        INSERT INTO wallet_transactions(user_id,type,amount_cents,description)
        VALUES(?,?,?,?)
      `).bind(userId,txType,amount,reason).run();

      try{
        await env.DB.prepare(`
          UPDATE users SET balance_cents=balance_cents ${type==="credit"?"+":"-"} ?,updated_at=CURRENT_TIMESTAMP
          WHERE id=? ${type==="debit"?"AND balance_cents>=?":""}
        `).bind(...(type==="debit"?[amount,userId,amount]:[amount,userId])).run();

        await env.DB.prepare(`
          INSERT INTO wallet_adjustments(user_id,admin_id,type,amount_cents,reason)
          VALUES(?,?,?,?,?)
        `).bind(userId,adminId,type,amount,reason).run();

        await env.DB.prepare(`
          INSERT INTO audit_logs(actor_user_id,action,target_user_id,details)
          VALUES(?,?,?,?)
        `).bind(adminId,type==="credit"?"admin_wallet_credit":"admin_wallet_debit",userId,JSON.stringify({amount_cents:amount,reason,transaction_id:result.meta.last_row_id})).run();
      }catch(e){
        return json({ok:false,error:"Não foi possível concluir a alteração financeira."},500,cors);
      }

      await createNotification(env,userId,"system",type==="credit"?"💰 Saldo creditado":"💸 Saldo debitado",
        `${type==="credit"?"Foi adicionado":"Foi retirado"} R$ ${(amount/100).toFixed(2).replace(".",",")} da sua carteira.`,{reason});
      return json({ok:true,message:"Carteira atualizada com sucesso."},200,cors);
    }


    if(url.pathname==="/api/admin/wallet/check" && request.method==="GET"){
      const adminId=await readSession(request,env);
      if(!adminId)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==adminId)return json({ok:false,error:"Acesso negado."},403,cors);

      const rows=await env.DB.prepare(`
        SELECT u.id,u.name,u.balance_cents,
          COALESCE(SUM(CASE WHEN wt.type IN ('credit','game_reward','referral_reward','admin_credit','withdrawal_refund') THEN wt.amount_cents
                            WHEN wt.type IN ('debit','admin_debit') THEN -wt.amount_cents
                            ELSE 0 END),0) AS ledger_net
        FROM users u
        LEFT JOIN wallet_transactions wt ON wt.user_id=u.id
        WHERE u.status='active'
        GROUP BY u.id
        HAVING u.balance_cents != ledger_net
        ORDER BY u.id DESC LIMIT 100
      `).all();
      return json({ok:true,inconsistencies:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/wallet/user" && request.method==="GET"){
      const adminId=await readSession(request,env);
      if(!adminId)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==adminId)return json({ok:false,error:"Acesso negado."},403,cors);
      const userId=Math.floor(Number(url.searchParams.get("user_id")));
      if(!Number.isInteger(userId)||userId<1)return json({ok:false,error:"Usuário inválido."},400,cors);
      const summary=await walletSummary(env,userId);
      const rows=await env.DB.prepare(`
        SELECT id,type,amount_cents,reference_id,description,created_at
        FROM wallet_transactions WHERE user_id=? ORDER BY id DESC LIMIT 100
      `).bind(userId).all();
      return json({ok:true,summary,transactions:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/wallet" && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      const user=await env.DB.prepare(
        "SELECT id,balance_cents,status FROM users WHERE id=?"
      ).bind(id).first();
      if(!user||user.status!=="active") return json({ok:false,error:"Conta indisponível."},403,cors);
      const tx=await env.DB.prepare(`
        SELECT id,type,amount_cents,description,created_at
        FROM wallet_transactions WHERE user_id=? ORDER BY id DESC LIMIT 100
      `).bind(id).all();
      const pending=await env.DB.prepare(`
        SELECT COALESCE(SUM(amount_cents),0) amount
        FROM withdrawal_requests WHERE user_id=? AND status='pending'
      `).bind(id).first();
      return json({ok:true,balance_cents:Number(user.balance_cents||0),
        pending_withdrawal_cents:Number(pending?.amount||0),transactions:tx.results||[]},200,cors);
    }

    if(await maintenanceGuard()) return await maintenanceGuard();
    
    async function getWithdrawalSettings(env){
      return await env.DB.prepare("SELECT * FROM withdrawal_settings WHERE id=1").first();
    }

    async function withdrawalDailyTotal(env,userId){
      const r=await env.DB.prepare(`
        SELECT COALESCE(SUM(amount_cents),0) total
        FROM withdrawal_requests
        WHERE user_id=? AND status IN ('pending','approved')
          AND date(created_at)=date('now')
      `).bind(userId).first();
      return Number(r?.total||0);
    }

    async function withdrawalCreate(env,userId,amountCents){
      const settings=await getWithdrawalSettings(env);
      if(!settings?.enabled) return {ok:false,error:"Os saques estão temporariamente indisponíveis."};
      if(amountCents<Number(settings.min_amount_cents))
        return {ok:false,error:`O saque mínimo é R$ ${(settings.min_amount_cents/100).toFixed(2).replace(".",",")}.`};
      if(amountCents>Number(settings.max_amount_cents))
        return {ok:false,error:"O valor excede o limite por saque."};

      const user=await env.DB.prepare(`
        SELECT balance_cents,status,pix_key FROM users WHERE id=?
      `).bind(userId).first();
      if(!user||user.status!=="active") return {ok:false,error:"Conta indisponível."};
      if(!user.pix_key) return {ok:false,error:"Cadastre sua chave Pix antes de solicitar."};
      if(Number(user.balance_cents)<amountCents) return {ok:false,error:"Saldo insuficiente."};

      const daily=await withdrawalDailyTotal(env,userId);
      if(daily+amountCents>Number(settings.daily_limit_cents))
        return {ok:false,error:"Você atingiu o limite diário de saques."};

      const recent=await env.DB.prepare(`
        SELECT id FROM withdrawal_requests
        WHERE user_id=? AND status='pending'
          AND created_at>=datetime('now',?)
        LIMIT 1
      `).bind(userId,`-${Math.max(0,Number(settings.cooldown_minutes))} minutes`).first();
      if(recent) return {ok:false,error:"Você já possui um saque pendente recente."};

      // Reserve the money and create the request atomically.
      try{
        const tx=await env.DB.prepare(`
          UPDATE users SET balance_cents=balance_cents-?,updated_at=CURRENT_TIMESTAMP
          WHERE id=? AND status='active' AND balance_cents>=?
        `).bind(amountCents,userId,amountCents).run();
        if(Number(tx.meta?.changes||0)!==1) return {ok:false,error:"O saldo mudou. Tente novamente."};

        const ins=await env.DB.prepare(`
          INSERT INTO withdrawal_requests(user_id,amount_cents,status)
          VALUES(?,?,'pending')
        `).bind(userId,amountCents).run();
        const withdrawalId=Number(ins.meta?.last_row_id||0);

        await env.DB.prepare(`
          INSERT INTO wallet_transactions(user_id,type,amount_cents,reference_id,description)
          VALUES(?,'withdrawal_hold',?,?,?)
        `).bind(userId,amountCents,String(withdrawalId),"Valor reservado para saque").run();

        await env.DB.prepare(`
          INSERT INTO withdrawal_audit(withdrawal_id,actor_user_id,action,amount_cents,note)
          VALUES(?,?, 'created',?,?)
        `).bind(withdrawalId,userId,amountCents,"Solicitação criada e valor reservado.").run();

        await createNotification(env,userId,"withdrawal","💸 Saque solicitado",
          `Seu saque de R$ ${(amountCents/100).toFixed(2).replace(".",",")} está pendente de análise.`,{withdrawal_id:withdrawalId});

        return {ok:true,withdrawal_id:withdrawalId};
      }catch(e){
        console.error("WITHDRAW_CREATE_ERROR",String(e));
        // Do not blindly refund here: a later consistency/audit process can identify
        // a partial operation. This avoids double-crediting money.
        return {ok:false,error:"Não foi possível criar o saque com segurança."};
      }
    }

if(url.pathname==="/api/withdrawals" && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      const rows=await env.DB.prepare(`
        SELECT id,amount_cents,pix_key,pix_type,status,admin_note,created_at,processed_at
        FROM withdrawal_requests WHERE user_id=? ORDER BY id DESC LIMIT 100
      `).bind(id).all();
      return json({ok:true,withdrawals:rows.results||[]},200,cors);
    }

    if(await maintenanceGuard()) return await maintenanceGuard();
    if(url.pathname==="/api/withdrawals" && request.method==="POST") {
      if((await platformSetting("withdrawals_enabled","1"))!=="1") return json({ok:false,error:"Os saques estão temporariamente desativados."},503,cors);
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);

      const body=await request.json();
      const amount=Number(body.amount_cents);
      const pixKey=String(body.pix_key||"").trim().slice(0,200);
      const pixType=String(body.pix_type||"manual").toLowerCase();

      if(!Number.isInteger(amount)||amount<=0||amount>100000000)
        return json({ok:false,error:"Valor de saque inválido."},400,cors);
      if(pixKey.length<3) return json({ok:false,error:"Informe uma chave PIX válida."},400,cors);
      if(!["cpf","cnpj","email","phone","random","manual"].includes(pixType))
        return json({ok:false,error:"Tipo de PIX inválido."},400,cors);

      const minSetting=await env.DB.prepare("SELECT value FROM settings WHERE key='withdrawal_min_cents'").first();
      const min=Math.max(0,Number(minSetting?.value||1500));
      if(amount<min)
        return json({ok:false,error:`O saque mínimo é R$ ${(min/100).toFixed(2).replace('.',',')}.`},400,cors);

      const user=await env.DB.prepare("SELECT balance_cents,status FROM users WHERE id=?").bind(id).first();
      if(!user||user.status!=="active") return json({ok:false,error:"Conta indisponível."},403,cors);
      if(Number(user.balance_cents)<amount)
        return json({ok:false,error:"Saldo insuficiente."},400,cors);

      const pending=await env.DB.prepare(
        "SELECT COUNT(*) c FROM withdrawal_requests WHERE user_id=? AND status='pending'"
      ).bind(id).first();
      if(Number(pending?.c||0)>0)
        return json({ok:false,error:"Você já possui um saque pendente."},409,cors);

      const result=await env.DB.prepare(`
        INSERT INTO withdrawal_requests(user_id,amount_cents,pix_key,pix_type)
        VALUES(?,?,?,?)`).bind(id,amount,pixKey,pixType).run();
      const withdrawalId=result.meta.last_row_id;

      await env.DB.batch([
        env.DB.prepare("UPDATE users SET balance_cents=balance_cents-?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND balance_cents>=?")
          .bind(amount,id,amount),
        env.DB.prepare("INSERT INTO wallet_transactions(user_id,type,amount_cents,reference_id,description) VALUES(?,?,?,?,?)")
          .bind(id,"withdrawal_hold",amount,withdrawalId,"Valor reservado para saque pendente")
      ]);
      await createNotification(env,id,"withdrawal","💸 Saque solicitado",`Seu saque de R$ ${(amount/100).toFixed(2).replace(".",",")} foi enviado para análise.`);
      return json({ok:true,message:"Saque solicitado e enviado para análise.",withdrawal_id:withdrawalId},200,cors);
    }

    if(url.pathname==="/api/withdrawals/cancel" && request.method==="POST") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      const body=await request.json(); const wid=Number(body.withdrawal_id);
      const row=await env.DB.prepare("SELECT * FROM withdrawal_requests WHERE id=? AND user_id=?").bind(wid,id).first();
      if(!row) return json({ok:false,error:"Saque não encontrado."},404,cors);
      if(row.status!=="pending") return json({ok:false,error:"Somente saques pendentes podem ser cancelados."},409,cors);
      await env.DB.batch([
        env.DB.prepare("UPDATE withdrawal_requests SET status='cancelled',processed_at=CURRENT_TIMESTAMP WHERE id=?").bind(wid),
        env.DB.prepare("UPDATE users SET balance_cents=balance_cents+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(row.amount_cents,id),
        env.DB.prepare("INSERT INTO wallet_transactions(user_id,type,amount_cents,reference_id,description) VALUES(?,?,?,?,?)").bind(id,"withdrawal_refund",row.amount_cents,wid,"Estorno de saque cancelado")
      ]);
      return json({ok:true,message:"Saque cancelado e saldo devolvido."},200,cors);
    }

    if(url.pathname==="/api/admin/withdrawals" && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id) return json({ok:false,error:"Acesso negado."},403,cors);
      const status=String(url.searchParams.get("status")||"pending");
      const allowed=["pending","approved","rejected","cancelled","all"];
      if(!allowed.includes(status)) return json({ok:false,error:"Status inválido."},400,cors);
      const query=status==="all"?`
        SELECT w.*,u.name user_name,u.email user_email FROM withdrawal_requests w
        JOIN users u ON u.id=w.user_id ORDER BY w.id DESC LIMIT 200
      `:`
        SELECT w.*,u.name user_name,u.email user_email FROM withdrawal_requests w
        JOIN users u ON u.id=w.user_id WHERE w.status=? ORDER BY w.id DESC LIMIT 200
      `;
      const rows=status==="all"?await env.DB.prepare(query).all():await env.DB.prepare(query).bind(status).all();
      return json({ok:true,withdrawals:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/withdrawals/process" && request.method==="POST") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id) return json({ok:false,error:"Acesso negado."},403,cors);

      const body=await request.json();
      const wid=Number(body.withdrawal_id);
      const action=String(body.action||"").toLowerCase();
      const note=String(body.note||"").trim().slice(0,500);
      if(!Number.isInteger(wid)||!["approve","reject"].includes(action))
        return json({ok:false,error:"Dados inválidos."},400,cors);

      const row=await env.DB.prepare("SELECT * FROM withdrawal_requests WHERE id=?").bind(wid).first();
      if(!row) return json({ok:false,error:"Saque não encontrado."},404,cors);
      if(row.status!=="pending") return json({ok:false,error:"Esse saque já foi processado."},409,cors);

      if(action==="approve"){
        await env.DB.batch([
          env.DB.prepare("UPDATE withdrawal_requests SET status='approved',admin_note=?,processed_at=CURRENT_TIMESTAMP,processed_by=? WHERE id=?").bind(note||null,id,wid),
          env.DB.prepare("INSERT INTO wallet_transactions(user_id,type,amount_cents,reference_id,description) VALUES(?,?,?,?,?)").bind(row.user_id,"debit",row.amount_cents,wid,"Saque aprovado"),
          env.DB.prepare("INSERT INTO admin_actions(admin_user_id,action,target_user_id,amount_cents,reason) VALUES(?,?,?,?,?)").bind(id,"approve_withdrawal",row.user_id,row.amount_cents,note||null),
          env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)").bind(id,"approve_withdrawal",row.user_id,JSON.stringify({withdrawal_id:wid,amount_cents:row.amount_cents}))
        ]);
        await createNotification(env,row.user_id,"withdrawal","✅ Saque aprovado",`Seu saque de R$ ${(row.amount_cents/100).toFixed(2).replace(".",",")} foi aprovado.`);
        return json({ok:true,message:"Saque aprovado. Realize o pagamento ao usuário conforme o seu processo de atendimento."},200,cors);
      }

      await env.DB.batch([
        env.DB.prepare("UPDATE withdrawal_requests SET status='rejected',admin_note=?,processed_at=CURRENT_TIMESTAMP,processed_by=? WHERE id=?").bind(note||"Saque rejeitado.",id,wid),
        env.DB.prepare("UPDATE users SET balance_cents=balance_cents+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(row.amount_cents,row.user_id),
        env.DB.prepare("INSERT INTO wallet_transactions(user_id,type,amount_cents,reference_id,description) VALUES(?,?,?,?,?)").bind(row.user_id,"withdrawal_refund",row.amount_cents,wid,"Estorno de saque rejeitado"),
        env.DB.prepare("INSERT INTO admin_actions(admin_user_id,action,target_user_id,amount_cents,reason) VALUES(?,?,?,?,?)").bind(id,"reject_withdrawal",row.user_id,row.amount_cents,note||null),
        env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)").bind(id,"reject_withdrawal",row.user_id,JSON.stringify({withdrawal_id:wid,amount_cents:row.amount_cents,reason:note||null}))
      ]);
      await createNotification(env,row.user_id,"withdrawal","❌ Saque rejeitado",`Seu saque de R$ ${(row.amount_cents/100).toFixed(2).replace(".",",")} foi rejeitado. O saldo foi devolvido.`);
      return json({ok:true,message:"Saque rejeitado e saldo devolvido."},200,cors);
    }

    if(url.pathname==="/api/admin/withdrawal-settings" && request.method==="POST") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id) return json({ok:false,error:"Acesso negado."},403,cors);
      const body=await request.json(); const min=Number(body.min_cents);
      if(!Number.isInteger(min)||min<0||min>100000000) return json({ok:false,error:"Valor mínimo inválido."},400,cors);
      await env.DB.prepare("INSERT INTO settings(key,value,updated_at) VALUES('withdrawal_min_cents',?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP").bind(String(min)).run();
      return json({ok:true,message:"Saque mínimo atualizado."},200,cors);
    }


    if(await maintenanceGuard()) return await maintenanceGuard();
    if(url.pathname==="/api/tickets" && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      const rows=await env.DB.prepare(`
        SELECT id,subject,status,priority,assigned_admin,last_message_at,created_at,closed_at
        FROM tickets WHERE user_id=? ORDER BY last_message_at DESC LIMIT 50
      `).bind(id).all();
      return json({ok:true,tickets:rows.results||[]},200,cors);
    }

    if(await maintenanceGuard()) return await maintenanceGuard();
    if(url.pathname==="/api/tickets" && request.method==="POST") {
      if((await platformSetting("tickets_enabled","1"))!=="1") return json({ok:false,error:"O suporte está temporariamente desativado."},503,cors);
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      const body=await request.json();
      const subject=String(body.subject||"").trim().slice(0,120);
      const message=String(body.message||"").trim().slice(0,4000);
      const priority=["low","normal","high","urgent"].includes(String(body.priority||"normal"))?String(body.priority):"normal";
      if(subject.length<3||message.length<1)return json({ok:false,error:"Informe assunto e mensagem."},400,cors);

      const setting=await env.DB.prepare("SELECT value FROM settings WHERE key='ticket_max_open_per_user'").first();
      const max=Math.max(1,Number(setting?.value||3));
      const count=await env.DB.prepare("SELECT COUNT(*) c FROM tickets WHERE user_id=? AND status!='closed'").bind(id).first();
      if(Number(count?.c||0)>=max)return json({ok:false,error:`Você já possui ${max} chamados em aberto.`},409,cors);

      const result=await env.DB.prepare("INSERT INTO tickets(user_id,subject,priority) VALUES(?,?,?)").bind(id,subject,priority).run();
      const ticketId=result.meta.last_row_id;
      await env.DB.prepare("INSERT INTO ticket_messages(ticket_id,sender_type,sender_id,message) VALUES(?,?,?,?)")
        .bind(ticketId,"user",id,message).run();
      return json({ok:true,ticket_id:ticketId,message:"Chamado criado com sucesso."},200,cors);
    }

    if(url.pathname.match(/^\/api\/tickets\/\d+$/) && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const ticketId=Number(url.pathname.split("/").pop());
      const ticket=await env.DB.prepare(`
        SELECT id,subject,status,priority,assigned_admin,last_message_at,created_at,closed_at
        FROM tickets WHERE id=? AND user_id=?`).bind(ticketId,id).first();
      if(!ticket)return json({ok:false,error:"Chamado não encontrado."},404,cors);
      const messages=await env.DB.prepare(`
        SELECT id,sender_type,sender_id,message,created_at FROM ticket_messages
        WHERE ticket_id=? ORDER BY id ASC`).bind(ticketId).all();
      return json({ok:true,ticket,messages:messages.results||[]},200,cors);
    }

    if(url.pathname.match(/^\/api\/tickets\/\d+\/messages$/) && request.method==="POST") {
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const ticketId=Number(url.pathname.split("/")[3]);
      const body=await request.json();
      const message=String(body.message||"").trim().slice(0,4000);
      if(!message)return json({ok:false,error:"Digite uma mensagem."},400,cors);
      const ticket=await env.DB.prepare("SELECT id,status FROM tickets WHERE id=? AND user_id=?").bind(ticketId,id).first();
      if(!ticket)return json({ok:false,error:"Chamado não encontrado."},404,cors);
      if(ticket.status==="closed")return json({ok:false,error:"Este chamado está fechado."},409,cors);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO ticket_messages(ticket_id,sender_type,sender_id,message) VALUES(?,?,?,?)").bind(ticketId,"user",id,message),
        env.DB.prepare("UPDATE tickets SET status='open',last_message_at=CURRENT_TIMESTAMP WHERE id=?").bind(ticketId)
      ]);
      return json({ok:true,message:"Mensagem enviada."},200,cors);
    }

    if(url.pathname==="/api/admin/tickets" && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const status=String(url.searchParams.get("status")||"open");
      const allowed=["open","pending","closed","all"];
      if(!allowed.includes(status))return json({ok:false,error:"Status inválido."},400,cors);
      const query=status==="all"?`
        SELECT t.*,u.name user_name,u.email user_email FROM tickets t
        JOIN users u ON u.id=t.user_id ORDER BY t.last_message_at DESC LIMIT 200`
        :`SELECT t.*,u.name user_name,u.email user_email FROM tickets t
        JOIN users u ON u.id=t.user_id WHERE t.status=? ORDER BY t.last_message_at DESC LIMIT 200`;
      const rows=status==="all"?await env.DB.prepare(query).all():await env.DB.prepare(query).bind(status).all();
      return json({ok:true,tickets:rows.results||[]},200,cors);
    }

    if(url.pathname.match(/^\/api\/admin\/tickets\/\d+$/) && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const ticketId=Number(url.pathname.split("/").pop());
      const ticket=await env.DB.prepare(`
        SELECT t.*,u.name user_name,u.email user_email
        FROM tickets t JOIN users u ON u.id=t.user_id WHERE t.id=?`).bind(ticketId).first();
      if(!ticket)return json({ok:false,error:"Chamado não encontrado."},404,cors);
      const messages=await env.DB.prepare("SELECT id,sender_type,sender_id,message,created_at FROM ticket_messages WHERE ticket_id=? ORDER BY id ASC").bind(ticketId).all();
      return json({ok:true,ticket,messages:messages.results||[]},200,cors);
    }

    if(url.pathname.match(/^\/api\/admin\/tickets\/\d+\/messages$/) && request.method==="POST") {
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const ticketId=Number(url.pathname.split("/")[4]);
      const body=await request.json();
      const message=String(body.message||"").trim().slice(0,4000);
      if(!message)return json({ok:false,error:"Digite uma mensagem."},400,cors);
      const ticket=await env.DB.prepare("SELECT id,status FROM tickets WHERE id=?").bind(ticketId).first();
      if(!ticket)return json({ok:false,error:"Chamado não encontrado."},404,cors);
      if(ticket.status==="closed")return json({ok:false,error:"Este chamado está fechado."},409,cors);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO ticket_messages(ticket_id,sender_type,sender_id,message) VALUES(?,?,?,?)").bind(ticketId,"admin",id,message),
        env.DB.prepare("UPDATE tickets SET status='pending',assigned_admin=?,last_message_at=CURRENT_TIMESTAMP WHERE id=?").bind(id,ticketId)
      ]);
      await createNotification(env,ticket.user_id,"ticket","💬 Nova resposta no suporte",`O administrador respondeu ao ticket #${ticketId}.`);
      return json({ok:true,message:"Resposta enviada."},200,cors);
    }

    if(url.pathname.match(/^\/api\/admin\/tickets\/\d+\/status$/) && request.method==="POST") {
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const ticketId=Number(url.pathname.split("/")[4]);
      const body=await request.json();
      const status=String(body.status||"").toLowerCase();
      if(!["open","pending","closed"].includes(status))return json({ok:false,error:"Status inválido."},400,cors);
      const result=await env.DB.prepare("UPDATE tickets SET status=?,closed_at=CASE WHEN ?='closed' THEN CURRENT_TIMESTAMP ELSE NULL END,last_message_at=CURRENT_TIMESTAMP WHERE id=?").bind(status,status,ticketId).run();
      if(!result.meta.changes)return json({ok:false,error:"Chamado não encontrado."},404,cors);
      return json({ok:true,message:"Status atualizado."},200,cors);
    }


    async function platformSetting(key, fallback=null) {
      const row=await env.DB.prepare("SELECT value FROM platform_settings WHERE key=?").bind(key).first();
      return row ? row.value : fallback;
    }

    async function isMaintenance(env) {
      return (await platformSetting("maintenance_enabled","0"))==="1";
    }

    async function maintenanceGuard() {
      if(!(await isMaintenance(env))) return null;
      const id=await readSession(request,env);
      if(id && Number(env.ADMIN_USER_ID||0)===id) return null;
      const message=await platformSetting("maintenance_message","O sistema está em manutenção. Voltaremos em breve.");
      return json({ok:false,maintenance:true,error:message},503,cors);
    }

    if(url.pathname==="/api/platform/status" && request.method==="GET") {
      const id=await readSession(request,env);
      const maintenance=await isMaintenance(env);
      const settings={
        maintenance_message:await platformSetting("maintenance_message","O sistema está em manutenção."),
        registration_enabled:await platformSetting("registration_enabled","1"),
        referrals_enabled:await platformSetting("referrals_enabled","1"),
        games_enabled:await platformSetting("games_enabled","1"),
        withdrawals_enabled:await platformSetting("withdrawals_enabled","1"),
        tickets_enabled:await platformSetting("tickets_enabled","1")
      };
      return json({ok:true,maintenance,settings,is_admin:!!id&&Number(env.ADMIN_USER_ID||0)===id},200,cors);
    }


    if(url.pathname==="/api/admin/overview" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);

      const users=await env.DB.prepare("SELECT COUNT(*) c FROM users").first();
      const active=await env.DB.prepare("SELECT COUNT(*) c FROM users WHERE status='active'").first();
      const vip=await env.DB.prepare("SELECT COUNT(*) c FROM users WHERE plan='VIP' AND vip_until>CURRENT_TIMESTAMP").first();
      const balance=await env.DB.prepare("SELECT COALESCE(SUM(balance_cents),0) s FROM users WHERE status='active'").first();
      const pendingWithdrawals=await env.DB.prepare("SELECT COUNT(*) c,COALESCE(SUM(amount_cents),0) s FROM withdrawal_requests WHERE status='pending'").first();
      const openTickets=await env.DB.prepare("SELECT COUNT(*) c FROM tickets WHERE status!='closed'").first();
      const pendingReferrals=await env.DB.prepare("SELECT COUNT(*) c FROM referral_events WHERE status='pending'").first();
      const highRisk=await env.DB.prepare("SELECT COUNT(*) c FROM referral_risk_events WHERE risk_level='high'").first();
      const notifications=await env.DB.prepare("SELECT COUNT(*) c FROM notifications WHERE read_at IS NULL").first();

      const games=await env.DB.prepare(`
        SELECT game,COUNT(*) plays,COALESCE(SUM(reward_cents),0) rewards
        FROM game_plays WHERE created_at>=datetime('now','-24 hours') GROUP BY game
      `).all().catch(()=>({results:[]}));

      return json({ok:true,metrics:{
        users:Number(users?.c||0),active_users:Number(active?.c||0),
        vip_users:Number(vip?.c||0),balance_cents:Number(balance?.s||0),
        pending_withdrawals:Number(pendingWithdrawals?.c||0),
        pending_withdrawal_cents:Number(pendingWithdrawals?.s||0),
        open_tickets:Number(openTickets?.c||0),
        pending_referrals:Number(pendingReferrals?.c||0),
        high_risk_referrals:Number(highRisk?.c||0),
        unread_notifications:Number(notifications?.c||0),
        games_24h:games.results||[]
      }},200,cors);
    }

    if(url.pathname==="/api/admin/users/search" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const q=String(url.searchParams.get("q")||"").trim().slice(0,100);
      if(q.length<1)return json({ok:false,error:"Informe uma busca."},400,cors);
      const numeric=/^\d+$/.test(q);
      const rows=numeric
        ? await env.DB.prepare(`SELECT id,name,email,plan,vip_until,balance_cents,coins,gems,xp,status,created_at FROM users WHERE id=? LIMIT 30`).bind(Number(q)).all()
        : await env.DB.prepare(`SELECT id,name,email,plan,vip_until,balance_cents,coins,gems,xp,status,created_at FROM users WHERE name LIKE ? OR email LIKE ? LIMIT 30`).bind("%"+q+"%","%"+q+"%").all();
      return json({ok:true,users:rows.results||[]},200,cors);
    }

    if(url.pathname.match(/^\/api\/admin\/users\/\d+\/status$/) && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const target=Number(url.pathname.split("/")[4]);
      const body=await request.json();
      const requestedStatus=String(body.status||"").toLowerCase();
      if(!["active","blocked","banned"].includes(requestedStatus))return json({ok:false,error:"Status inválido."},400,cors);
      const status=requestedStatus==="blocked"?"banned":requestedStatus;
      if(target===id)return json({ok:false,error:"O administrador não pode bloquear a própria conta."},400,cors);
      const r=await env.DB.prepare("UPDATE users SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(status,target).run();
      if(!r.meta.changes)return json({ok:false,error:"Usuário não encontrado."},404,cors);
      await env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)").bind(id,status==="blocked"?"block_user":"unblock_user",target,JSON.stringify({status})).run();
      return json({ok:true,message:status==="banned"?"Usuário bloqueado.":"Usuário desbloqueado."},200,cors);
    }

    if(url.pathname.match(/^\/api\/admin\/users\/\d+\/balance$/) && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const target=Number(url.pathname.split("/")[4]);
      const body=await request.json();
      const amount=Number(body.amount_cents);
      const reason=String(body.reason||"Ajuste administrativo").trim().slice(0,300);
      if(!Number.isInteger(amount)||amount===0||Math.abs(amount)>100000000)return json({ok:false,error:"Valor inválido."},400,cors);
      const user=await env.DB.prepare("SELECT id,balance_cents FROM users WHERE id=?").bind(target).first();
      if(!user)return json({ok:false,error:"Usuário não encontrado."},404,cors);
      if(amount<0 && Number(user.balance_cents)<Math.abs(amount))return json({ok:false,error:"Saldo insuficiente para débito."},400,cors);
      await env.DB.batch([
        env.DB.prepare("UPDATE users SET balance_cents=balance_cents+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(amount,target),
        env.DB.prepare("INSERT INTO wallet_transactions(user_id,type,amount_cents,description) VALUES(?,?,?,?)").bind(target,amount>0?"admin_credit":"admin_debit",Math.abs(amount),reason),
        env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)").bind(id,amount>0?"admin_credit":"admin_debit",target,JSON.stringify({amount_cents:amount,reason}))
      ]);
      await createNotification(env,target,"wallet",amount>0?"💰 Saldo adicionado":"💸 Ajuste de saldo",`${amount>0?"Foi adicionado":"Foi debitado"} R$ ${(Math.abs(amount)/100).toFixed(2).replace(".",",")} na sua conta. Motivo: ${reason}`);
      return json({ok:true,message:"Saldo atualizado."},200,cors);
    }

    if(url.pathname==="/api/admin/platform/settings" && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const rows=await env.DB.prepare("SELECT key,value,updated_at FROM platform_settings ORDER BY key").all();
      return json({ok:true,settings:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/platform/settings" && request.method==="POST") {
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const body=await request.json();
      const allowed=[
        "maintenance_enabled","maintenance_message","registration_enabled",
        "referrals_enabled","games_enabled","withdrawals_enabled","tickets_enabled"
      ];
      const changes=body.settings||{};
      const stmts=[];
      for(const key of allowed){
        if(changes[key]===undefined)continue;
        let value=String(changes[key]);
        if(key.endsWith("_enabled"))value=value==="1"||value==="true"?"1":"0";
        if(key==="maintenance_message")value=value.trim().slice(0,1000);
        if(!value && key==="maintenance_message")value="O sistema está em manutenção. Voltaremos em breve.";
        stmts.push(env.DB.prepare(`
          INSERT INTO platform_settings(key,value,updated_at,updated_by)
          VALUES(?,?,CURRENT_TIMESTAMP,?)
          ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP,updated_by=excluded.updated_by
        `).bind(key,value,id));
      }
      if(!stmts.length)return json({ok:false,error:"Nenhuma configuração enviada."},400,cors);
      stmts.push(env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)").bind(id,"update_platform_settings",id,JSON.stringify(changes)));
      await env.DB.batch(stmts);
      return json({ok:true,message:"Configurações atualizadas."},200,cors);
    }


    async function createNotification(env,userId,type,title,message,data=null){
      try{
        await env.DB.prepare(`
          INSERT INTO notifications(user_id,type,title,message,data_json)
          VALUES(?,?,?,?,?)
        `).bind(
          Number(userId),
          String(type||"system").slice(0,30),
          String(title||"Notificação").slice(0,150),
          String(message||"").slice(0,1000),
          data?JSON.stringify(data):null
        ).run();
      }catch(e){
        console.error("NOTIFICATION_ERROR",String(e));
      }
    }


    async function vipStatus(env,userId){
      const user=await env.DB.prepare(`
        SELECT plan,vip_until FROM users WHERE id=? AND status='active'
      `).bind(userId).first();
      const settings=await env.DB.prepare("SELECT * FROM vip_settings WHERE id=1").first();
      const benefits=await env.DB.prepare(`
        SELECT code,title,description FROM vip_benefits
        WHERE enabled=1 ORDER BY sort_order,id
      `).all();
      const now=new Date().toISOString().slice(0,19).replace("T"," ");
      const active=!!(user?.plan==="VIP" && user?.vip_until && String(user.vip_until)>now);
      return {
        active,
        plan:active?"VIP":"FREE",
        vip_until:active?user.vip_until:null,
        settings,
        benefits:benefits.results||[]
      };
    }

    if(url.pathname==="/api/vip" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      return json({ok:true,...await vipStatus(env,id)},200,cors);
    }

    if(url.pathname==="/api/admin/vip" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const settings=await env.DB.prepare("SELECT * FROM vip_settings WHERE id=1").first();
      const benefits=await env.DB.prepare("SELECT * FROM vip_benefits ORDER BY sort_order,id").all();
      return json({ok:true,settings,benefits:benefits.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/vip/settings" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json();
      const price=Math.floor(Number(b.price_cents));
      const days=Math.floor(Number(b.duration_days));
      const gameMult=Number(b.daily_game_multiplier);
      const scratchMult=Number(b.daily_scratch_multiplier);
      const bonusXP=Math.floor(Number(b.daily_bonus_xp));
      const rankingMult=Number(b.ranking_multiplier);
      const enabled=b.enabled===false||b.enabled==="0"?0:1;
      if(!Number.isInteger(price)||price<0||!Number.isInteger(days)||days<1||days>3650||
         !Number.isFinite(gameMult)||gameMult<1||gameMult>10||
         !Number.isFinite(scratchMult)||scratchMult<1||scratchMult>10||
         !Number.isInteger(bonusXP)||bonusXP<0||bonusXP>100000||
         !Number.isFinite(rankingMult)||rankingMult<1||rankingMult>10)
        return json({ok:false,error:"Configuração VIP inválida."},400,cors);

      await env.DB.prepare(`
        UPDATE vip_settings SET price_cents=?,duration_days=?,
          daily_game_multiplier=?,daily_scratch_multiplier=?,daily_bonus_xp=?,
          ranking_multiplier=?,enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=1
      `).bind(price,days,gameMult,scratchMult,bonusXP,rankingMult,enabled).run();

      await env.DB.prepare(`
        INSERT INTO audit_logs(actor_user_id,action,target_user_id,details)
        VALUES(?,?,?,?)
      `).bind(id,"update_vip_settings",id,JSON.stringify({price,days,gameMult,scratchMult,bonusXP,rankingMult,enabled})).run();

      return json({ok:true,message:"Configuração VIP atualizada."},200,cors);
    }

    if(url.pathname==="/api/admin/vip/benefits" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json();
      const code=String(b.code||"").trim().toLowerCase().slice(0,40);
      const title=String(b.title||"").trim().slice(0,100);
      const description=String(b.description||"").trim().slice(0,300);
      const order=Math.floor(Number(b.sort_order||0));
      const enabled=b.enabled===false||b.enabled==="0"?0:1;
      if(!/^[a-z0-9_-]{2,40}$/.test(code)||!title||!description||!Number.isInteger(order))
        return json({ok:false,error:"Dados do benefício inválidos."},400,cors);
      try{
        await env.DB.prepare(`
          INSERT INTO vip_benefits(code,title,description,enabled,sort_order)
          VALUES(?,?,?,?,?)
          ON CONFLICT(code) DO UPDATE SET title=excluded.title,description=excluded.description,
            enabled=excluded.enabled,sort_order=excluded.sort_order,updated_at=CURRENT_TIMESTAMP
        `).bind(code,title,description,enabled,order).run();
        return json({ok:true,message:"Benefício VIP salvo."},200,cors);
      }catch(e){return json({ok:false,error:"Não foi possível salvar o benefício."},500,cors)}
    }

    if(url.pathname==="/api/admin/vip/grant" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json();
      const userId=Math.floor(Number(b.user_id));
      const days=Math.floor(Number(b.days));
      if(!Number.isInteger(userId)||userId<1||!Number.isInteger(days)||days<1||days>3650)
        return json({ok:false,error:"Usuário ou duração inválidos."},400,cors);

      const user=await env.DB.prepare("SELECT vip_until FROM users WHERE id=? AND status='active'").bind(userId).first();
      if(!user)return json({ok:false,error:"Usuário não encontrado."},404,cors);

      const now=new Date();
      const before=user.vip_until && String(user.vip_until)>now.toISOString().slice(0,19).replace("T"," ") ? String(user.vip_until) : null;
      const base=before?new Date(before.replace(" ","T")+"Z"):now;
      base.setUTCDate(base.getUTCDate()+days);
      const after=base.toISOString().slice(0,19).replace("T"," ");

      await env.DB.batch([
        env.DB.prepare("UPDATE users SET plan='VIP',vip_until=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(after,userId),
        env.DB.prepare("INSERT INTO vip_redemptions(user_id,source,reference_code,days,vip_until_before,vip_until_after) VALUES(?,?,?,?,?,?)").bind(userId,"admin",null,days,before,after)
      ]);
      await createNotification(env,userId,"vip","👑 VIP ativado","Seu VIP foi ativado/estendido pelo administrador.",{days,vip_until:after});
      return json({ok:true,message:"VIP concedido com sucesso.",vip_until:after},200,cors);
    }


    async function getFraudSettings(env){
      return await env.DB.prepare("SELECT * FROM fraud_settings WHERE id=1").first();
    }

    async function fraudHash(value){
      const data=new TextEncoder().encode(String(value||""));
      const digest=await crypto.subtle.digest("SHA-256",data);
      return [...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,"0")).join("");
    }

    async function registerFraudEvent(env,userId,eventType,riskScore,details,action="log"){
      try{
        await env.DB.prepare(`
          INSERT INTO fraud_events(user_id,event_type,risk_score,details_json,action)
          VALUES(?,?,?,?,?)
        `).bind(
          userId||null,String(eventType).slice(0,60),
          Math.max(0,Math.min(100,Math.floor(riskScore||0))),
          details?JSON.stringify(details):null,
          ["log","review","block"].includes(action)?action:"log"
        ).run();
      }catch(e){ console.error("FRAUD_LOG_ERROR",String(e)); }
    }

    if(url.pathname==="/api/security/status" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const row=await env.DB.prepare(`
        SELECT status FROM users WHERE id=?
      `).bind(id).first();
      const events=await env.DB.prepare(`
        SELECT event_type,risk_score,action,created_at
        FROM fraud_events WHERE user_id=? ORDER BY id DESC LIMIT 10
      `).bind(id).all();
      return json({ok:true,status:row?.status||"unknown",events:events.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/fraud" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const settings=await getFraudSettings(env);
      const events=await env.DB.prepare(`
        SELECT f.*,u.name,u.email
        FROM fraud_events f LEFT JOIN users u ON u.id=f.user_id
        ORDER BY f.id DESC LIMIT 100
      `).all();
      return json({ok:true,settings,events:events.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/fraud/settings" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json();
      const enabled=b.enabled===false||b.enabled==="0"?0:1;
      const daily=Math.floor(Number(b.referral_daily_limit));
      const sameIp=Math.floor(Number(b.referral_same_ip_limit));
      const review=Math.floor(Number(b.max_risk_review));
      const block=Math.floor(Number(b.max_risk_block));
      if(![daily,sameIp,review,block].every(Number.isInteger) ||
         daily<1||daily>10000||sameIp<1||sameIp>100||review<1||review>99||block<=review||block>100)
        return json({ok:false,error:"Configuração antifraude inválida."},400,cors);

      await env.DB.prepare(`
        UPDATE fraud_settings SET enabled=?,referral_daily_limit=?,
        referral_same_ip_limit=?,max_risk_review=?,max_risk_block=?,
        updated_at=CURRENT_TIMESTAMP WHERE id=1
      `).bind(enabled,daily,sameIp,review,block).run();

      await env.DB.prepare(`
        INSERT INTO audit_logs(actor_user_id,action,target_user_id,details)
        VALUES(?,?,?,?)
      `).bind(id,"update_fraud_settings",id,JSON.stringify({enabled,daily,sameIp,review,block})).run();

      return json({ok:true,message:"Configuração antifraude salva."},200,cors);
    }


    function validUrl(value){
      try{const u=new URL(String(value||""));return ["https:","http:"].includes(u.protocol)?u.href:"";}catch(e){return "";}
    }

    async function activeAds(env,placement){
      const p=["home","dashboard","missions","ranking","vip"].includes(placement)?placement:"home";
      const rows=await env.DB.prepare(`
        SELECT a.id,a.title,a.description,a.image_url,a.target_url,a.placement,
               p.name partner_name,p.logo_url partner_logo
        FROM advertisements a
        LEFT JOIN partners p ON p.id=a.partner_id AND p.status='active'
        WHERE a.status='active'
          AND a.placement=?
          AND (a.starts_at IS NULL OR a.starts_at<=CURRENT_TIMESTAMP)
          AND (a.ends_at IS NULL OR a.ends_at>CURRENT_TIMESTAMP)
        ORDER BY a.sort_order,a.id DESC
        LIMIT 10
      `).bind(p).all();
      return rows.results||[];
    }

    if(url.pathname==="/api/ads" && request.method==="GET"){
      const id=await readSession(request,env);
      const placement=url.searchParams.get("placement")||"home";
      const ads=await activeAds(env,placement);
      // Count an impression only for an authenticated user and only once per ad per
      // short request window. This keeps the counter useful without inflating it.
      if(id && ads.length){
        for(const ad of ads.slice(0,5)){
          try{
            const recent=await env.DB.prepare(`
              SELECT id FROM ad_events
              WHERE ad_id=? AND user_id=? AND event_type='impression'
                AND created_at>=datetime('now','-30 minutes') LIMIT 1
            `).bind(ad.id,id).first();
            if(!recent){
              await env.DB.batch([
                env.DB.prepare("UPDATE advertisements SET impressions=impressions+1 WHERE id=?").bind(ad.id),
                env.DB.prepare("INSERT INTO ad_events(ad_id,user_id,event_type) VALUES(?,?, 'impression')").bind(ad.id,id)
              ]);
            }
          }catch(e){ console.error("AD_IMPRESSION_ERROR",String(e)); }
        }
      }
      return json({ok:true,ads},200,cors);
    }

    if(url.pathname==="/api/ads/click" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const b=await request.json().catch(()=>({}));
      const adId=Math.floor(Number(b.ad_id));
      if(!Number.isInteger(adId)||adId<1)return json({ok:false,error:"Anúncio inválido."},400,cors);
      const ad=await env.DB.prepare(`
        SELECT id,target_url FROM advertisements
        WHERE id=? AND status='active'
          AND (starts_at IS NULL OR starts_at<=CURRENT_TIMESTAMP)
          AND (ends_at IS NULL OR ends_at>CURRENT_TIMESTAMP)
      `).bind(adId).first();
      if(!ad)return json({ok:false,error:"Anúncio indisponível."},404,cors);
      const target=validUrl(ad.target_url);
      if(!target)return json({ok:false,error:"Destino do anúncio inválido."},409,cors);
      await env.DB.batch([
        env.DB.prepare("UPDATE advertisements SET clicks=clicks+1 WHERE id=?").bind(adId),
        env.DB.prepare("INSERT INTO ad_events(ad_id,user_id,event_type) VALUES(?,?, 'click')").bind(adId,id)
      ]);
      return json({ok:true,target_url:target},200,cors);
    }

    if(url.pathname==="/api/admin/partners" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const partners=await env.DB.prepare("SELECT * FROM partners ORDER BY sort_order,id DESC").all();
      const ads=await env.DB.prepare(`
        SELECT a.*,p.name partner_name FROM advertisements a
        LEFT JOIN partners p ON p.id=a.partner_id
        ORDER BY a.id DESC LIMIT 200
      `).all();
      return json({ok:true,partners:partners.results||[],ads:ads.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/partners" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json().catch(()=>({}));
      const partnerId=Math.floor(Number(b.id||0));
      const name=String(b.name||"").trim().slice(0,120);
      const logo=validUrl(b.logo_url);
      const site=validUrl(b.website_url);
      const description=String(b.description||"").trim().slice(0,500);
      const status=["active","paused","archived"].includes(String(b.status))?String(b.status):"active";
      const order=Math.floor(Number(b.sort_order||0));
      if(!name)return json({ok:false,error:"Nome da parceria é obrigatório."},400,cors);
      if(partnerId){
        await env.DB.prepare(`
          UPDATE partners SET name=?,logo_url=?,website_url=?,description=?,status=?,sort_order=?,updated_at=CURRENT_TIMESTAMP
          WHERE id=?
        `).bind(name,logo||null,site||null,description,status,order,partnerId).run();
      }else{
        await env.DB.prepare(`
          INSERT INTO partners(name,logo_url,website_url,description,status,sort_order)
          VALUES(?,?,?,?,?,?)
        `).bind(name,logo||null,site||null,description,status,order).run();
      }
      await env.DB.prepare(`
        INSERT INTO audit_logs(actor_user_id,action,target_user_id,details)
        VALUES(?,?,?,?)
      `).bind(id,"manage_partner",id,JSON.stringify({partnerId,name,status})).run();
      return json({ok:true,message:"Parceria salva."},200,cors);
    }

    if(url.pathname==="/api/admin/ads" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json().catch(()=>({}));
      const adId=Math.floor(Number(b.id||0));
      const partnerId=Math.floor(Number(b.partner_id||0))||null;
      const title=String(b.title||"").trim().slice(0,150);
      const description=String(b.description||"").trim().slice(0,500);
      const image=validUrl(b.image_url);
      const target=validUrl(b.target_url);
      const placement=["home","dashboard","missions","ranking","vip"].includes(String(b.placement))?String(b.placement):"home";
      const starts=b.starts_at?String(b.starts_at).slice(0,30):null;
      const ends=b.ends_at?String(b.ends_at).slice(0,30):null;
      const status=["active","paused","archived"].includes(String(b.status))?String(b.status):"active";
      if(!title||!target)return json({ok:false,error:"Título e destino são obrigatórios."},400,cors);
      if(adId){
        await env.DB.prepare(`
          UPDATE advertisements SET partner_id=?,title=?,description=?,image_url=?,target_url=?,
          placement=?,starts_at=?,ends_at=?,status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?
        `).bind(partnerId,title,description,image||null,target,placement,starts,ends,status,adId).run();
      }else{
        await env.DB.prepare(`
          INSERT INTO advertisements(partner_id,title,description,image_url,target_url,placement,starts_at,ends_at,status)
          VALUES(?,?,?,?,?,?,?,?,?)
        `).bind(partnerId,title,description,image||null,target,placement,starts,ends,status).run();
      }
      await env.DB.prepare(`
        INSERT INTO audit_logs(actor_user_id,action,target_user_id,details)
        VALUES(?,?,?,?)
      `).bind(id,"manage_advertisement",id,JSON.stringify({adId,title,placement,status})).run();
      return json({ok:true,message:"Publicidade salva."},200,cors);
    }



    async function securitySettings(env){
      return await env.DB.prepare("SELECT * FROM security_settings WHERE id=1").first();
    }

    async function securityLog(env,userId,eventType,severity,details={},request=null){
      try{
        // Do not store raw IPs or other unnecessary identifiers.
        let ipHash=null;
        const ip=request?.headers?.get("CF-Connecting-IP")||"";
        if(ip && env.SECURITY_SALT){
          const data=new TextEncoder().encode(ip+String(env.SECURITY_SALT));
          const digest=await crypto.subtle.digest("SHA-256",data);
          ipHash=[...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,"0")).join("");
        }
        await env.DB.prepare(`
          INSERT INTO security_events(user_id,event_type,severity,fingerprint,ip_hash,details)
          VALUES(?,?,?,?,?,?)
        `).bind(userId||null,eventType,severity,null,ipHash,JSON.stringify(details).slice(0,2000)).run();
      }catch(e){console.error("SECURITY_LOG_ERROR",String(e));}
    }

    async function securityCount(env,tableColumn,userId,minutes){
      const safeCol=tableColumn==="ticket"?"sender_id":"user_id";
      const table=tableColumn==="ticket"?"ticket_messages":"security_events";
      const extra=tableColumn==="ticket"?" AND sender_type='user'":"";
      const r=await env.DB.prepare(`
        SELECT COUNT(*) c FROM ${table}
        WHERE ${safeCol}=? ${extra} AND created_at>=datetime('now',?)
      `).bind(userId,`-${Math.max(1,minutes)} minutes`).first();
      return Number(r?.c||0);
    }

    async function securityAllow(env,userId,type,request=null){
      const st=await securitySettings(env);
      if(!st?.enabled)return true;
      let limit=Number(st.max_requests_minute), minutes=1;
      if(type==="ticket_message"){limit=Number(st.max_ticket_messages_minute);minutes=1;}
      const count=await securityCount(env,"generic",userId,minutes);
      if(count>=limit){
        await securityLog(env,userId,"rate_limit", "warning",{type,count,limit},request);
        return false;
      }
      return true;
    }

    async function isAdmin(env,userId){
      return Number(env.ADMIN_USER_ID||0)===Number(userId||0);
    }

    if(url.pathname==="/api/system/status" && request.method==="GET"){
      const maintenance=(await platformSetting("maintenance_enabled","0"))==="1";
      const message=await platformSetting(env,"maintenance_message","Sistema em manutenção. Voltaremos em breve.");
      return json({ok:true,maintenance,message},200,cors);
    }

    if(url.pathname==="/api/admin/system" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(!(await isAdmin(env,id)))return json({ok:false,error:"Acesso negado."},403,cors);
      const settings=await env.DB.prepare(`
        SELECT key,value,updated_at,updated_by FROM platform_settings
        WHERE key IN ('maintenance_enabled','maintenance_message','maintenance_allow_admin')
        ORDER BY key
      `).all();

      const users=await env.DB.prepare("SELECT COUNT(*) c FROM users").first();
      const active=await env.DB.prepare("SELECT COUNT(*) c FROM users WHERE status='active'").first();
      const tickets=await env.DB.prepare("SELECT COUNT(*) c FROM tickets WHERE status IN ('open','pending')").first();
      const withdrawals=await env.DB.prepare("SELECT COUNT(*) c FROM withdrawal_requests WHERE status='pending'").first();
      const today=await env.DB.prepare("SELECT COUNT(*) c FROM users WHERE date(created_at)=date('now')").first();

      return json({
        ok:true,
        settings:settings.results||[],
        metrics:{
          users:Number(users?.c||0),
          active_users:Number(active?.c||0),
          open_tickets:Number(tickets?.c||0),
          pending_withdrawals:Number(withdrawals?.c||0),
          registrations_today:Number(today?.c||0)
        }
      },200,cors);
    }

    if(url.pathname==="/api/admin/system/maintenance" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(!(await isAdmin(env,id)))return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json().catch(()=>({}));
      const enabled=b.enabled===true||b.enabled==="1"? "1":"0";
      const message=String(b.message||"Sistema em manutenção. Voltaremos em breve.").trim().slice(0,500);
      const allowAdmin=b.allow_admin===false||b.allow_admin==="0"?"0":"1";

      await env.DB.batch([
        env.DB.prepare(`INSERT INTO platform_settings(key,value,updated_at,updated_by) VALUES('maintenance_enabled',?,CURRENT_TIMESTAMP,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP,updated_by=excluded.updated_by`).bind(enabled,id),
        env.DB.prepare(`INSERT INTO platform_settings(key,value,updated_at,updated_by) VALUES('maintenance_message',?,CURRENT_TIMESTAMP,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP,updated_by=excluded.updated_by`).bind(message,id),
        env.DB.prepare(`INSERT INTO platform_settings(key,value,updated_at,updated_by) VALUES('maintenance_allow_admin',?,CURRENT_TIMESTAMP,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP,updated_by=excluded.updated_by`).bind(allowAdmin,id),
        env.DB.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)`).bind(id,"update_maintenance",id,JSON.stringify({enabled,allowAdmin,message}))
      ]);
      return json({ok:true,message:enabled==="1"?"Modo manutenção ativado.":"Modo manutenção desativado."},200,cors);
    }

    if(url.pathname==="/api/admin/health" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(!(await isAdmin(env,id)))return json({ok:false,error:"Acesso negado."},403,cors);
      const checks=[];
      try{
        await env.DB.prepare("SELECT 1").first();
        checks.push({name:"Banco D1",status:"ok",details:"Consulta de teste executada."});
      }catch(e){checks.push({name:"Banco D1",status:"error",details:"Falha na consulta."});}

      try{
        const required=["users","wallet_transactions","withdrawal_requests","tickets","notifications","vip_settings"];
        for(const t of required) await env.DB.prepare(`SELECT 1 FROM ${t} LIMIT 1`).first();
        checks.push({name:"Tabelas essenciais",status:"ok",details:"Estrutura essencial acessível."});
      }catch(e){checks.push({name:"Tabelas essenciais",status:"error",details:"Uma ou mais tabelas não puderam ser consultadas."});}

      try{
        const stuck=await env.DB.prepare(`
          SELECT COUNT(*) c FROM withdrawal_requests
          WHERE status='pending' AND created_at<datetime('now','-7 days')
        `).first();
        checks.push({name:"Saques pendentes antigos",status:Number(stuck?.c||0)>0?"warning":"ok",details:`${Number(stuck?.c||0)} saque(s) pendente(s) há mais de 7 dias.`});
      }catch(e){checks.push({name:"Saques",status:"warning",details:"Não foi possível analisar pendências."});}

      try{
        const tickets=await env.DB.prepare(`
          SELECT COUNT(*) c FROM tickets WHERE status IN ('open','pending') AND last_message_at<datetime('now','-7 days')
        `).first();
        checks.push({name:"Tickets antigos",status:Number(tickets?.c||0)>0?"warning":"ok",details:`${Number(tickets?.c||0)} ticket(s) sem atividade há mais de 7 dias.`});
      }catch(e){checks.push({name:"Tickets",status:"warning",details:"Não foi possível analisar tickets."});}

      for(const c of checks){
        try{await env.DB.prepare("INSERT INTO system_health_checks(check_name,status,details) VALUES(?,?,?)").bind(c.name,c.status,c.details).run();}catch(e){}
      }
      return json({ok:true,checked_at:new Date().toISOString(),checks},200,cors);
    }

    if(url.pathname==="/api/admin/export" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(!(await isAdmin(env,id)))return json({ok:false,error:"Acesso negado."},403,cors);

      // Safe operational export: intentionally excludes password_hash and other secrets.
      const tables=["users","referral_events","referral_rewards","wallet_transactions","withdrawal_requests","tickets","ticket_messages","notifications","promo_codes","promo_redemptions","partners","advertisements","ad_events","vip_settings","vip_benefits","vip_redemptions","fraud_events","audit_logs"];
      const exportData={generated_at:new Date().toISOString(),tables:{}};
      for(const t of tables){
        try{
          let rows=await env.DB.prepare(`SELECT * FROM ${t} LIMIT 5000`).all();
          if(t==="users") rows={results:(rows.results||[]).map(u=>{const x={...u};delete x.password_hash;return x;})};
          exportData.tables[t]=rows.results||[];
        }catch(e){exportData.tables[t]=[];}
      }
      await env.DB.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)`)
        .bind(id,"admin_safe_export",id,JSON.stringify({tables:tables.length})).run();
      return json({ok:true,...exportData},200,cors);
    }


    async function ticketSettings(env){
      return await env.DB.prepare("SELECT * FROM ticket_settings WHERE id=1").first();
    }

    async function ticketCanAccess(env,ticketId,userId,admin=false){
      const t=await env.DB.prepare("SELECT * FROM tickets WHERE id=?").bind(ticketId).first();
      if(!t)return null;
      if(admin)return t;
      return Number(t.user_id)===Number(userId)?t:null;
    }

    if(url.pathname==="/api/tickets" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const admin=await isAdmin(env,id);
      if(admin){
        const rows=await env.DB.prepare(`
          SELECT t.*,u.name,u.email
          FROM tickets t JOIN users u ON u.id=t.user_id
          ORDER BY CASE t.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END,
                   CASE t.status WHEN 'open' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END,
                   t.last_message_at DESC
          LIMIT 200
        `).all();
        return json({ok:true,tickets:rows.results||[],admin:true},200,cors);
      }
      const rows=await env.DB.prepare(`
        SELECT * FROM tickets WHERE user_id=? ORDER BY last_message_at DESC LIMIT 50
      `).bind(id).all();
      return json({ok:true,tickets:rows.results||[],admin:false},200,cors);
    }

    if(url.pathname==="/api/tickets" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(!(await securityAllow(env,id,"request",request)))return json({ok:false,error:"Muitas solicitações. Aguarde um momento."},429,cors);
      const settings=await ticketSettings(env);
      if(!settings?.enabled)return json({ok:false,error:"O suporte está temporariamente indisponível."},503,cors);

      const b=await request.json().catch(()=>({}));
      const subject=String(b.subject||"").trim().slice(0,150);
      const message=String(b.message||"").trim().slice(0,3000);
      const priority=["low","normal","high","urgent"].includes(String(b.priority))?String(b.priority):"normal";
      if(subject.length<3||message.length<3)return json({ok:false,error:"Informe assunto e mensagem."},400,cors);

      const open=await env.DB.prepare(`
        SELECT COUNT(*) c FROM tickets WHERE user_id=? AND status IN ('open','pending')
      `).bind(id).first();
      if(Number(open?.c||0)>=Number(settings.max_open_per_user))
        return json({ok:false,error:"Você atingiu o limite de tickets abertos."},409,cors);

      const recent=await env.DB.prepare(`
        SELECT id FROM ticket_messages WHERE sender_type='user' AND sender_id=?
        AND created_at>=datetime('now',?) LIMIT 1
      `).bind(id,`-${Math.max(0,Number(settings.cooldown_seconds))} seconds`).first();
      if(recent)return json({ok:false,error:"Aguarde alguns segundos antes de enviar outro ticket."},429,cors);

      try{
        const ins=await env.DB.prepare(`
          INSERT INTO tickets(user_id,subject,status,priority) VALUES(?,?,'open',?)
        `).bind(id,subject,priority).run();
        const ticketId=Number(ins.meta?.last_row_id||0);
        await env.DB.prepare(`
          INSERT INTO ticket_messages(ticket_id,sender_type,sender_id,message) VALUES(?,'user',?,?)
        `).bind(ticketId,id,message).run();
        await createNotification(env,id,"support","🎫 Ticket criado",`Seu ticket #${ticketId} foi criado e está aguardando atendimento.`,{ticket_id:ticketId});
        return json({ok:true,ticket_id:ticketId},200,cors);
      }catch(e){
        console.error("TICKET_CREATE_ERROR",String(e));
        return json({ok:false,error:"Não foi possível criar o ticket."},500,cors);
      }
    }

    if(url.pathname==="/api/tickets/message" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const admin=await isAdmin(env,id);
      if(!admin && !(await securityAllow(env,id,"ticket_message",request)))return json({ok:false,error:"Muitas mensagens em pouco tempo. Aguarde."},429,cors);
      const b=await request.json().catch(()=>({}));
      const ticketId=Math.floor(Number(b.ticket_id));
      const message=String(b.message||"").trim().slice(0,3000);
      if(!Number.isInteger(ticketId)||ticketId<1||message.length<1)return json({ok:false,error:"Mensagem inválida."},400,cors);

      const ticket=await ticketCanAccess(env,ticketId,id,admin);
      if(!ticket)return json({ok:false,error:"Ticket não encontrado ou sem acesso."},404,cors);
      if(ticket.status==="closed")return json({ok:false,error:"Este ticket está fechado."},409,cors);

      const senderType=admin?"admin":"user";
      await env.DB.prepare(`
        INSERT INTO ticket_messages(ticket_id,sender_type,sender_id,message)
        VALUES(?,?,?,?)
      `).bind(ticketId,senderType,id,message).run();

      await env.DB.prepare(`
        UPDATE tickets SET status=?,assigned_admin=?,last_message_at=CURRENT_TIMESTAMP
        WHERE id=?
      `).bind(admin?"pending":"open",admin?id:ticket.assigned_admin,ticketId).run();

      if(admin){
        await createNotification(env,Number(ticket.user_id),"support","💬 Resposta do suporte",`O suporte respondeu ao seu ticket #${ticketId}.`,{ticket_id:ticketId});
      }else if(ticket.assigned_admin){
        await createNotification(env,Number(ticket.assigned_admin),"support","💬 Nova mensagem","Um usuário respondeu a um ticket.",{ticket_id:ticketId});
      }
      return json({ok:true,message:"Mensagem enviada."},200,cors);
    }

    if(url.pathname==="/api/tickets/messages" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const admin=await isAdmin(env,id);
      const ticketId=Math.floor(Number(url.searchParams.get("ticket_id")));
      if(!Number.isInteger(ticketId)||ticketId<1)return json({ok:false,error:"Ticket inválido."},400,cors);
      const ticket=await ticketCanAccess(env,ticketId,id,admin);
      if(!ticket)return json({ok:false,error:"Ticket não encontrado ou sem acesso."},404,cors);
      const rows=await env.DB.prepare(`
        SELECT id,sender_type,sender_id,message,created_at
        FROM ticket_messages WHERE ticket_id=? ORDER BY id ASC LIMIT 500
      `).bind(ticketId).all();
      return json({ok:true,ticket,messages:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/tickets/action" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(!(await isAdmin(env,id)))return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json().catch(()=>({}));
      const ticketId=Math.floor(Number(b.ticket_id));
      const action=String(b.action||"");
      if(!Number.isInteger(ticketId)||ticketId<1||!["assign","close","reopen","priority"].includes(action))
        return json({ok:false,error:"Ação inválida."},400,cors);

      const t=await env.DB.prepare("SELECT * FROM tickets WHERE id=?").bind(ticketId).first();
      if(!t)return json({ok:false,error:"Ticket não encontrado."},404,cors);

      if(action==="assign"){
        await env.DB.prepare("UPDATE tickets SET assigned_admin=?,status='pending' WHERE id=?").bind(id,ticketId).run();
      }else if(action==="close"){
        await env.DB.prepare("UPDATE tickets SET status='closed',assigned_admin=?,closed_at=CURRENT_TIMESTAMP WHERE id=?").bind(id,ticketId).run();
      }else if(action==="reopen"){
        await env.DB.prepare("UPDATE tickets SET status='open',closed_at=NULL WHERE id=?").bind(ticketId).run();
      }else{
        const priority=["low","normal","high","urgent"].includes(String(b.priority))?String(b.priority):"normal";
        await env.DB.prepare("UPDATE tickets SET priority=? WHERE id=?").bind(priority,ticketId).run();
      }
      await env.DB.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)`)
        .bind(id,"ticket_"+action,Number(t.user_id),JSON.stringify({ticket_id:ticketId})).run();
      if(action==="close"||action==="reopen")
        await createNotification(env,Number(t.user_id),"support",action==="close"?"🎫 Ticket encerrado":"🎫 Ticket reaberto",`O ticket #${ticketId} foi ${action==="close"?"encerrado":"reaberto"} pelo suporte.`,{ticket_id:ticketId});
      return json({ok:true,message:"Ticket atualizado."},200,cors);
    }

    if(url.pathname==="/api/admin/ticket-settings" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(!(await isAdmin(env,id)))return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json().catch(()=>({}));
      const enabled=b.enabled===false||b.enabled==="0"?0:1;
      const max=Math.floor(Number(b.max_open_per_user));
      const cooldown=Math.floor(Number(b.cooldown_seconds));
      if(!Number.isInteger(max)||max<1||max>20||!Number.isInteger(cooldown)||cooldown<0||cooldown>3600)
        return json({ok:false,error:"Configuração de suporte inválida."},400,cors);
      await env.DB.prepare(`
        UPDATE ticket_settings SET enabled=?,max_open_per_user=?,cooldown_seconds=?,updated_at=CURRENT_TIMESTAMP WHERE id=1
      `).bind(enabled,max,cooldown).run();
      return json({ok:true,message:"Configuração de tickets salva."},200,cors);
    }



    if(url.pathname==="/api/admin/audit" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(!(await isAdmin(env,id)))return json({ok:false,error:"Acesso negado."},403,cors);

      const limit=Math.min(300,Math.max(1,Number(url.searchParams.get("limit")||100)));
      const action=String(url.searchParams.get("action")||"").trim().slice(0,80);
      const actor=Math.floor(Number(url.searchParams.get("actor_id")||0));

      let rows;
      if(action){
        rows=await env.DB.prepare(`
          SELECT a.id,a.actor_user_id,a.action,a.target_user_id,a.details,a.created_at,
                 ua.name actor_name,ut.name target_name
          FROM audit_logs a
          LEFT JOIN users ua ON ua.id=a.actor_user_id
          LEFT JOIN users ut ON ut.id=a.target_user_id
          WHERE a.action=? ORDER BY a.id DESC LIMIT ?
        `).bind(action,limit).all();
      }else if(actor>0){
        rows=await env.DB.prepare(`
          SELECT a.id,a.actor_user_id,a.action,a.target_user_id,a.details,a.created_at,
                 ua.name actor_name,ut.name target_name
          FROM audit_logs a
          LEFT JOIN users ua ON ua.id=a.actor_user_id
          LEFT JOIN users ut ON ut.id=a.target_user_id
          WHERE a.actor_user_id=? ORDER BY a.id DESC LIMIT ?
        `).bind(actor,limit).all();
      }else{
        rows=await env.DB.prepare(`
          SELECT a.id,a.actor_user_id,a.action,a.target_user_id,a.details,a.created_at,
                 ua.name actor_name,ut.name target_name
          FROM audit_logs a
          LEFT JOIN users ua ON ua.id=a.actor_user_id
          LEFT JOIN users ut ON ut.id=a.target_user_id
          ORDER BY a.id DESC LIMIT ?
        `).bind(limit).all();
      }
      return json({ok:true,logs:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/notes" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(!(await isAdmin(env,id)))return json({ok:false,error:"Acesso negado."},403,cors);
      const target=Math.floor(Number(url.searchParams.get("user_id")||0));
      const rows=target>0
        ? await env.DB.prepare(`
            SELECT n.*,u.name admin_name FROM admin_notes n
            LEFT JOIN users u ON u.id=n.admin_id
            WHERE n.target_user_id=? ORDER BY n.id DESC LIMIT 100
          `).bind(target).all()
        : await env.DB.prepare(`
            SELECT n.*,u.name admin_name FROM admin_notes n
            LEFT JOIN users u ON u.id=n.admin_id
            ORDER BY n.id DESC LIMIT 100
          `).all();
      return json({ok:true,notes:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/notes" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(!(await isAdmin(env,id)))return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json().catch(()=>({}));
      const target=Math.floor(Number(b.user_id||0))||null;
      const note=String(b.note||"").trim().slice(0,1000);
      if(!note)return json({ok:false,error:"A anotação não pode ficar vazia."},400,cors);
      if(target){
        const user=await env.DB.prepare("SELECT id FROM users WHERE id=?").bind(target).first();
        if(!user)return json({ok:false,error:"Usuário não encontrado."},404,cors);
      }
      await env.DB.prepare(`
        INSERT INTO admin_notes(admin_id,target_user_id,note) VALUES(?,?,?)
      `).bind(id,target,note).run();
      await env.DB.prepare(`
        INSERT INTO audit_logs(actor_user_id,action,target_user_id,details)
        VALUES(?,?,?,?)
      `).bind(id,"admin_note_created",target,JSON.stringify({note_length:note.length})).run();
      return json({ok:true,message:"Anotação salva."},200,cors);
    }

    if(url.pathname==="/api/admin/security" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(!(await isAdmin(env,id)))return json({ok:false,error:"Acesso negado."},403,cors);
      const settings=await securitySettings(env);
      const events=await env.DB.prepare(`
        SELECT s.*,u.name FROM security_events s
        LEFT JOIN users u ON u.id=s.user_id
        ORDER BY s.id DESC LIMIT 100
      `).all();
      const stats=await env.DB.prepare(`
        SELECT event_type,severity,COUNT(*) total
        FROM security_events
        WHERE created_at>=datetime('now','-24 hours')
        GROUP BY event_type,severity ORDER BY total DESC
      `).all();
      return json({ok:true,settings,events:events.results||[],stats:stats.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/security" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(!(await isAdmin(env,id)))return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json().catch(()=>({}));
      const enabled=b.enabled===false||b.enabled==="0"?0:1;
      const max=Math.floor(Number(b.max_requests_minute||60));
      const tickets=Math.floor(Number(b.max_ticket_messages_minute||10));
      const refs=Math.floor(Number(b.max_referral_actions_hour||20));
      if(max<1||max>10000||tickets<1||tickets>1000||refs<1||refs>1000)
        return json({ok:false,error:"Limites de segurança inválidos."},400,cors);
      await env.DB.prepare(`
        UPDATE security_settings SET enabled=?,max_requests_minute=?,max_ticket_messages_minute=?,max_referral_actions_hour=?,updated_at=CURRENT_TIMESTAMP
        WHERE id=1
      `).bind(enabled,max,tickets,refs).run();
      await securityLog(env,id,"security_settings_changed","info",{enabled,max,tickets,refs},request);
      await env.DB.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)`)
        .bind(id,"security_settings_changed",id,JSON.stringify({enabled,max,tickets,refs})).run();
      return json({ok:true,message:"Configurações de segurança salvas."},200,cors);
    }

    if(url.pathname==="/api/notifications" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const rows=await env.DB.prepare(`
        SELECT id,type,title,message,read_at,created_at
        FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100
      `).bind(id).all();
      const unread=await env.DB.prepare(
        "SELECT COUNT(*) c FROM notifications WHERE user_id=? AND read_at IS NULL"
      ).bind(id).first();
      return json({ok:true,notifications:rows.results||[],unread:Number(unread?.c||0)},200,cors);
    }

    if(url.pathname==="/api/notifications/read" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const body=await request.json();
      if(body.all){
        await env.DB.prepare("UPDATE notifications SET read_at=CURRENT_TIMESTAMP WHERE user_id=? AND read_at IS NULL").bind(id).run();
      }else{
        const nid=Number(body.id);
        if(!Number.isInteger(nid))return json({ok:false,error:"Notificação inválida."},400,cors);
        await env.DB.prepare("UPDATE notifications SET read_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?").bind(nid,id).run();
      }
      return json({ok:true},200,cors);
    }

    if(url.pathname==="/api/notifications/preferences" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      let p=await env.DB.prepare("SELECT * FROM notification_preferences WHERE user_id=?").bind(id).first();
      if(!p){
        await env.DB.prepare("INSERT OR IGNORE INTO notification_preferences(user_id) VALUES(?)").bind(id).run();
        p=await env.DB.prepare("SELECT * FROM notification_preferences WHERE user_id=?").bind(id).first();
      }
      return json({ok:true,preferences:p},200,cors);
    }

    if(url.pathname==="/api/notifications/preferences" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const b=await request.json();
      const keys=["referrals","wallet","withdrawals","vip","tickets","games","system"];
      const vals={}; for(const k of keys) vals[k]=b[k]===false||b[k]==="0"?0:1;
      await env.DB.prepare(`
        INSERT INTO notification_preferences(user_id,referrals,wallet,withdrawals,vip,tickets,games,system)
        VALUES(?,?,?,?,?,?,?,?)
        ON CONFLICT(user_id) DO UPDATE SET
        referrals=excluded.referrals,wallet=excluded.wallet,withdrawals=excluded.withdrawals,
        vip=excluded.vip,tickets=excluded.tickets,games=excluded.games,system=excluded.system
      `).bind(id,vals.referrals,vals.wallet,vals.withdrawals,vals.vip,vals.tickets,vals.games,vals.system).run();
      return json({ok:true,message:"Preferências atualizadas."},200,cors);
    }



    async function getUserLevel(env,xp){
      const row=await env.DB.prepare(`
        SELECT level,xp_required,title FROM level_settings
        WHERE xp_required<=? ORDER BY level DESC LIMIT 1
      `).bind(Number(xp||0)).first();
      const next=await env.DB.prepare(`
        SELECT level,xp_required,title FROM level_settings
        WHERE xp_required>? ORDER BY xp_required ASC LIMIT 1
      `).bind(Number(xp||0)).first();
      return {
        level:Number(row?.level||1),
        title:row?.title||"Iniciante",
        xp_required:Number(row?.xp_required||0),
        next_level:next?Number(next.level):null,
        next_xp:next?Number(next.xp_required):null,
        progress_to_next:next?Math.max(0,Math.min(100,((Number(xp||0)-Number(row?.xp_required||0))/(Number(next.xp_required)-Number(row?.xp_required||0)))*100)):100
      };
    }

    async function unlockAchievements(env,userId){
      const user=await env.DB.prepare("SELECT xp FROM users WHERE id=?").bind(userId).first();
      if(!user)return [];
      const refs=await env.DB.prepare("SELECT COUNT(*) c FROM referral_events WHERE referrer_id=? AND status='approved'").bind(userId).first();
      const achievements=await env.DB.prepare("SELECT * FROM achievements WHERE enabled=1").all();
      const unlocked=[];
      for(const a of (achievements.results||[])){
        const current=a.requirement_type==="xp"?Number(user.xp||0):Number(refs?.c||0);
        if(current<Number(a.requirement_value))continue;
        const exists=await env.DB.prepare("SELECT id FROM user_achievements WHERE user_id=? AND achievement_id=?").bind(userId,a.id).first();
        if(exists)continue;
        const stmts=[
          env.DB.prepare("INSERT INTO user_achievements(user_id,achievement_id) VALUES(?,?)").bind(userId,a.id)
        ];
        if(a.reward_type==="balance")stmts.push(env.DB.prepare("UPDATE users SET balance_cents=balance_cents+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(a.reward_value,userId));
        if(a.reward_type==="coins")stmts.push(env.DB.prepare("UPDATE users SET coins=coins+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(a.reward_value,userId));
        if(a.reward_type==="gems")stmts.push(env.DB.prepare("UPDATE users SET gems=gems+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(a.reward_value,userId));
        await env.DB.batch(stmts);
        await createNotification(env,userId,"system",`${a.icon} Conquista desbloqueada`,`${a.title}: ${a.description}`);
        unlocked.push(a);
      }
      return unlocked;
    }


    async function awardXP(env,userId,action,referenceId=null){
      const rule=await env.DB.prepare(
        "SELECT * FROM xp_rules WHERE action=? AND enabled=1"
      ).bind(action).first();
      if(!rule || Number(rule.xp)<=0) return {awarded:0,reason:"disabled"};

      if(Number(rule.daily_limit)>0){
        const count=await env.DB.prepare(`
          SELECT COUNT(*) c FROM xp_events
          WHERE user_id=? AND action=? AND date(created_at)=date('now')
        `).bind(userId,action).first();
        if(Number(count?.c||0)>=Number(rule.daily_limit))
          return {awarded:0,reason:"daily_limit"};
      }

      try{
        await env.DB.batch([
          env.DB.prepare(`
            INSERT INTO xp_events(user_id,action,xp,reference_id)
            VALUES(?,?,?,?)
          `).bind(userId,action,Number(rule.xp),referenceId===null?null:String(referenceId)),
          env.DB.prepare(`
            UPDATE users SET xp=COALESCE(xp,0)+?,updated_at=CURRENT_TIMESTAMP
            WHERE id=?
          `).bind(Number(rule.xp),userId)
        ]);
        await unlockAchievements(env,userId);
        return {awarded:Number(rule.xp),reason:"ok"};
      }catch(e){
        if(String(e).toLowerCase().includes("unique"))
          return {awarded:0,reason:"already_awarded"};
        throw e;
      }
    }

    if(url.pathname==="/api/daily-login" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);

      const user=await env.DB.prepare(`
        SELECT plan,vip_until FROM users WHERE id=? AND status='active'
      `).bind(id).first();
      if(!user)return json({ok:false,error:"Conta indisponível."},403,cors);

      const today=await env.DB.prepare(`
        SELECT login_xp FROM daily_activity
        WHERE user_id=? AND activity_date=date('now')
      `).bind(id).first();

      if(today){
        return json({ok:true,awarded:0,message:"O bônus diário já foi recebido hoje."},200,cors);
      }

      const isVip=user.plan==="VIP" && user.vip_until &&
        String(user.vip_until)>String(new Date().toISOString().slice(0,19).replace("T"," "));

      const action=isVip?"vip_login":"daily_login";
      const result=await awardXP(env,id,action,"daily:"+new Date().toISOString().slice(0,10));

      await env.DB.prepare(`
        INSERT OR REPLACE INTO daily_activity(user_id,activity_date,login_xp)
        VALUES(?,?,?)
      `).bind(id,new Date().toISOString().slice(0,10),result.awarded).run();

      return json({
        ok:true,
        awarded:result.awarded,
        message:result.awarded>0
          ?`Você ganhou ${result.awarded} XP pelo acesso de hoje!`
          :"O bônus diário já foi processado."
      },200,cors);
    }

    if(url.pathname==="/api/xp/history" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const rows=await env.DB.prepare(`
        SELECT action,xp,reference_id,created_at
        FROM xp_events WHERE user_id=? ORDER BY id DESC LIMIT 100
      `).bind(id).all();
      return json({ok:true,history:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/xp-rules" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const rows=await env.DB.prepare("SELECT * FROM xp_rules ORDER BY action").all();
      return json({ok:true,rules:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/xp-rules" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);

      const b=await request.json();
      const action=String(b.action||"").trim().toLowerCase().slice(0,50);
      const xp=Math.floor(Number(b.xp));
      const dailyLimit=Math.floor(Number(b.daily_limit||0));
      const enabled=b.enabled===false||b.enabled==="0"?0:1;
      const description=String(b.description||"").trim().slice(0,200);

      if(!/^[a-z0-9_-]{2,50}$/.test(action))
        return json({ok:false,error:"Ação inválida."},400,cors);
      if(!Number.isInteger(xp)||xp<0||xp>100000)
        return json({ok:false,error:"XP inválido."},400,cors);
      if(!Number.isInteger(dailyLimit)||dailyLimit<0||dailyLimit>10000)
        return json({ok:false,error:"Limite diário inválido."},400,cors);

      await env.DB.prepare(`
        INSERT INTO xp_rules(action,xp,daily_limit,enabled,description)
        VALUES(?,?,?,?,?)
        ON CONFLICT(action) DO UPDATE SET
          xp=excluded.xp,
          daily_limit=excluded.daily_limit,
          enabled=excluded.enabled,
          description=excluded.description,
          updated_at=CURRENT_TIMESTAMP
      `).bind(action,xp,dailyLimit,enabled,description).run();

      await env.DB.prepare(`
        INSERT INTO audit_logs(actor_user_id,action,target_user_id,details)
        VALUES(?,?,?,?)
      `).bind(id,"update_xp_rule",id,JSON.stringify({action,xp,dailyLimit,enabled})).run();

      return json({ok:true,message:"Regra de XP salva."},200,cors);
    }


    function missionPeriodKey(period){
      const d=new Date();
      const day=d.toISOString().slice(0,10);
      if(period==="daily") return day;
      const jan=new Date(Date.UTC(d.getUTCFullYear(),0,1));
      const week=Math.ceil((((d-jan)/86400000)+jan.getUTCDay()+1)/7);
      return `${d.getUTCFullYear()}-W${String(week).padStart(2,"0")}`;
    }

    async function getMissionStats(env,userId,mission){
      let value=0;
      const periodKey=missionPeriodKey(mission.period);

      if(mission.requirement_type==="login_days"){
        const row=await env.DB.prepare(`
          SELECT COUNT(*) c FROM daily_activity
          WHERE user_id=? AND activity_date=?
        `).bind(userId,periodKey).first();
        value=Number(row?.c||0);
        if(value===0){
          const xp=await env.DB.prepare(`
            SELECT COUNT(*) c FROM xp_events
            WHERE user_id=? AND action IN ('daily_login','vip_login')
              AND date(created_at)=date('now')
          `).bind(userId).first();
          value=Number(xp?.c||0);
        }
      }else if(mission.requirement_type==="xp"){
        const row=await env.DB.prepare("SELECT xp FROM users WHERE id=?").bind(userId).first();
        value=Number(row?.xp||0);
      }else if(mission.requirement_type==="referrals"){
        const row=await env.DB.prepare(`
          SELECT COUNT(*) c FROM referral_events
          WHERE referrer_id=? AND status='approved'
            AND strftime('%Y-%W',created_at)=strftime('%Y-%W','now')
        `).bind(userId).first();
        value=Number(row?.c||0);
      }else if(mission.requirement_type==="games"){
        const row=await env.DB.prepare(`
          SELECT COUNT(*) c FROM xp_events
          WHERE user_id=? AND action='game_play' AND date(created_at)=date('now')
        `).bind(userId).first();
        value=Number(row?.c||0);
      }
      return {periodKey,value};
    }

    async function refreshMissions(env,userId){
      const rows=await env.DB.prepare("SELECT * FROM missions WHERE enabled=1").all();
      const result=[];
      for(const mission of (rows.results||[])){
        const st=await getMissionStats(env,userId,mission);
        let p=await env.DB.prepare(`
          SELECT * FROM mission_progress
          WHERE mission_id=? AND user_id=? AND period_key=?
        `).bind(mission.id,userId,st.periodKey).first();

        const progress=Math.min(Number(mission.requirement_value),st.value);
        if(!p){
          await env.DB.prepare(`
            INSERT INTO mission_progress(mission_id,user_id,period_key,progress,completed_at)
            VALUES(?,?,?,?,?)
          `).bind(
            mission.id,userId,st.periodKey,progress,
            progress>=Number(mission.requirement_value)?"CURRENT_TIMESTAMP":null
          ).run();
          p=await env.DB.prepare(`
            SELECT * FROM mission_progress WHERE mission_id=? AND user_id=? AND period_key=?
          `).bind(mission.id,userId,st.periodKey).first();
        }else if(progress!==Number(p.progress)){
          await env.DB.prepare(`
            UPDATE mission_progress SET progress=?,
              completed_at=CASE WHEN ? >= ? AND completed_at IS NULL THEN CURRENT_TIMESTAMP ELSE completed_at END,
              updated_at=CURRENT_TIMESTAMP
            WHERE id=?
          `).bind(progress,progress,Number(mission.requirement_value),p.id).run();
          p={...p,progress,completed_at:p.completed_at||(progress>=Number(mission.requirement_value)?new Date().toISOString():null)};
        }

        result.push({...mission,period_key:st.periodKey,progress,completed_at:p?.completed_at||null,claimed_at:p?.claimed_at||null});
      }
      return result;
    }


    function rankingKey(period){
      const d=new Date();
      if(period==="daily") return d.toISOString().slice(0,10);
      if(period==="monthly") return d.toISOString().slice(0,7);
      const jan=new Date(Date.UTC(d.getUTCFullYear(),0,1));
      const week=Math.ceil((((d-jan)/86400000)+jan.getUTCDay()+1)/7);
      return `${d.getUTCFullYear()}-W${String(week).padStart(2,"0")}`;
    }

    async function rankingRows(env,period){
      const key=rankingKey(period);
      let where="";
      if(period==="daily") where="date(x.created_at)=date('now')";
      else if(period==="monthly") where="strftime('%Y-%m',x.created_at)=strftime('%Y-%m','now')";
      else where="strftime('%Y-%W',x.created_at)=strftime('%Y-%W','now')";

      const rows=await env.DB.prepare(`
        SELECT x.user_id,u.name,u.username,COALESCE(SUM(x.xp),0) score
        FROM xp_events x JOIN users u ON u.id=x.user_id
        WHERE ${where} AND u.status='active'
        GROUP BY x.user_id
        ORDER BY score DESC,u.id ASC
        LIMIT 100
      `).all();
      return {key,rows:rows.results||[]};
    }


    if(url.pathname==="/api/notifications" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const limit=Math.min(100,Math.max(1,Number(url.searchParams.get("limit")||30)));
      const rows=await env.DB.prepare(`
        SELECT id,type,title,message,data_json,is_read,created_at
        FROM notifications
        WHERE user_id=? ORDER BY id DESC LIMIT ?
      `).bind(id,limit).all();
      const unread=await env.DB.prepare(`
        SELECT COUNT(*) c FROM notifications WHERE user_id=? AND is_read=0
      `).bind(id).first();
      return json({ok:true,notifications:rows.results||[],unread:Number(unread?.c||0)},200,cors);
    }

    if(url.pathname==="/api/notifications/read" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const body=await request.json().catch(()=>({}));
      const notificationId=Number(body.id||0);
      if(notificationId){
        const r=await env.DB.prepare(`
          UPDATE notifications SET is_read=1
          WHERE id=? AND user_id=?
        `).bind(notificationId,id).run();
        return json({ok:true,updated:Number(r.meta?.changes||0)},200,cors);
      }
      await env.DB.prepare(`
        UPDATE notifications SET is_read=1 WHERE user_id=? AND is_read=0
      `).bind(id).run();
      return json({ok:true,updated_all:true},200,cors);
    }

    if(url.pathname==="/api/notifications/delete" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const body=await request.json().catch(()=>({}));
      const notificationId=Number(body.id||0);
      if(!notificationId)return json({ok:false,error:"Notificação inválida."},400,cors);
      await env.DB.prepare(`
        DELETE FROM notifications WHERE id=? AND user_id=?
      `).bind(notificationId,id).run();
      return json({ok:true},200,cors);
    }

    if(url.pathname==="/api/ranking" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const period=["daily","weekly","monthly"].includes(url.searchParams.get("period")||"daily")
        ?url.searchParams.get("period"):"daily";
      const data=await rankingRows(env,period);
      const ranking=data.rows.map((r,i)=>({...r,position:i+1}));
      const me=ranking.find(r=>Number(r.user_id)===id)||null;
      const rewards=await env.DB.prepare(`
        SELECT position,reward_type,reward_value FROM ranking_rewards
        WHERE period=? AND enabled=1 ORDER BY position
      `).bind(period).all();
      return json({ok:true,period,period_key:data.key,ranking,me,rewards:rewards.results||[]},200,cors);
    }

    if(url.pathname==="/api/ranking/claim" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const body=await request.json().catch(()=>({}));
      const period=["daily","weekly","monthly"].includes(String(body.period))?String(body.period):"daily";
      const data=await rankingRows(env,period);
      const index=data.rows.findIndex(r=>Number(r.user_id)===id);
      if(index<0 || index>=100)return json({ok:false,error:"Você ainda não possui posição no ranking."},409,cors);
      const position=index+1;
      const reward=await env.DB.prepare(`
        SELECT * FROM ranking_rewards
        WHERE period=? AND position=? AND enabled=1
      `).bind(period,position).first();
      if(!reward)return json({ok:false,error:"Sua posição não possui recompensa."},409,cors);

      const existing=await env.DB.prepare(`
        SELECT id FROM ranking_claims WHERE user_id=? AND period=? AND period_key=?
      `).bind(id,period,data.key).first();
      if(existing)return json({ok:false,error:"A recompensa deste período já foi resgatada."},409,cors);

      const stmts=[];
      if(reward.reward_type==="xp")
        stmts.push(env.DB.prepare("UPDATE users SET xp=COALESCE(xp,0)+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(reward.reward_value,id));
      else if(reward.reward_type==="coins")
        stmts.push(env.DB.prepare("UPDATE users SET coins=COALESCE(coins,0)+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(reward.reward_value,id));
      else if(reward.reward_type==="gems")
        stmts.push(env.DB.prepare("UPDATE users SET gems=COALESCE(gems,0)+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(reward.reward_value,id));
      else
        stmts.push(env.DB.prepare("UPDATE users SET balance_cents=balance_cents+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(reward.reward_value,id));

      stmts.push(env.DB.prepare(`
        INSERT INTO ranking_claims(user_id,period,period_key,position,reward_type,reward_value)
        VALUES(?,?,?,?,?,?)
      `).bind(id,period,data.key,position,reward.reward_type,reward.reward_value));

      try{ await env.DB.batch(stmts); }
      catch(e){ return json({ok:false,error:"A recompensa não pôde ser processada."},500,cors); }

      await createNotification(env,id,"system","🏆 Recompensa do ranking",`Você ficou em ${position}º lugar e recebeu ${reward.reward_value} ${reward.reward_type}.`);
      return json({ok:true,message:"Recompensa do ranking resgatada!"},200,cors);
    }

    if(url.pathname==="/api/admin/ranking-rewards" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const rows=await env.DB.prepare("SELECT * FROM ranking_rewards ORDER BY period,position").all();
      return json({ok:true,rewards:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/ranking-rewards" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json();
      const period=["daily","weekly","monthly"].includes(String(b.period))?String(b.period):"daily";
      const position=Math.floor(Number(b.position));
      const rewardType=["xp","coins","gems","balance"].includes(String(b.reward_type))?String(b.reward_type):"coins";
      const rewardValue=Math.floor(Number(b.reward_value));
      const enabled=b.enabled===false||b.enabled==="0"?0:1;
      if(!Number.isInteger(position)||position<1||position>100||!Number.isInteger(rewardValue)||rewardValue<1)
        return json({ok:false,error:"Dados da recompensa inválidos."},400,cors);

      await env.DB.prepare(`
        INSERT INTO ranking_rewards(period,position,reward_type,reward_value,enabled)
        VALUES(?,?,?,?,?)
        ON CONFLICT(period,position) DO UPDATE SET
          reward_type=excluded.reward_type,
          reward_value=excluded.reward_value,
          enabled=excluded.enabled
      `).bind(period,position,rewardType,rewardValue,enabled).run();

      await env.DB.prepare(`
        INSERT INTO audit_logs(actor_user_id,action,target_user_id,details)
        VALUES(?,?,?,?)
      `).bind(id,"update_ranking_reward",id,JSON.stringify({period,position,rewardType,rewardValue,enabled})).run();

      return json({ok:true,message:"Recompensa do ranking salva."},200,cors);
    }

    if(url.pathname==="/api/missions" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const missions=await refreshMissions(env,id);
      return json({ok:true,missions},200,cors);
    }

    if(url.pathname.match(/^\/api\/missions\/\d+\/claim$/) && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const missionId=Number(url.pathname.split("/")[3]);
      const mission=await env.DB.prepare("SELECT * FROM missions WHERE id=? AND enabled=1").bind(missionId).first();
      if(!mission)return json({ok:false,error:"Missão não encontrada."},404,cors);

      const missions=await refreshMissions(env,id);
      const current=missions.find(x=>Number(x.id)===missionId);
      if(!current || Number(current.progress)<Number(mission.requirement_value))
        return json({ok:false,error:"Missão ainda não foi concluída."},409,cors);
      if(current.claimed_at)
        return json({ok:false,error:"Essa missão já foi resgatada neste período."},409,cors);

      const progress=await env.DB.prepare(`
        SELECT * FROM mission_progress
        WHERE mission_id=? AND user_id=? AND period_key=?
      `).bind(missionId,id,current.period_key).first();

      const stmts=[];
      if(mission.reward_type==="xp")
        stmts.push(env.DB.prepare("UPDATE users SET xp=COALESCE(xp,0)+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(mission.reward_value,id));
      else if(mission.reward_type==="coins")
        stmts.push(env.DB.prepare("UPDATE users SET coins=COALESCE(coins,0)+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(mission.reward_value,id));
      else if(mission.reward_type==="gems")
        stmts.push(env.DB.prepare("UPDATE users SET gems=COALESCE(gems,0)+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(mission.reward_value,id));
      else
        stmts.push(env.DB.prepare("UPDATE users SET balance_cents=balance_cents+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(mission.reward_value,id));

      stmts.push(env.DB.prepare(`
        UPDATE mission_progress SET claimed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP
        WHERE id=? AND claimed_at IS NULL
      `).bind(progress.id));

      try{
        await env.DB.batch(stmts);
      }catch(e){
        return json({ok:false,error:"Não foi possível resgatar a recompensa. Tente novamente."},500,cors);
      }

      await createNotification(env,id,"system","🎯 Missão concluída",`Você recebeu a recompensa de ${mission.reward_value} ${mission.reward_type}.`);
      return json({ok:true,message:"Recompensa resgatada com sucesso!"},200,cors);
    }

    if(url.pathname==="/api/admin/missions" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const rows=await env.DB.prepare("SELECT * FROM missions ORDER BY id DESC").all();
      return json({ok:true,missions:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/missions" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json();

      const code=String(b.code||"").trim().toUpperCase().replace(/\s+/g,"").slice(0,50);
      const title=String(b.title||"").trim().slice(0,100);
      const description=String(b.description||"").trim().slice(0,300);
      const period=["daily","weekly"].includes(String(b.period))?String(b.period):"daily";
      const requirementType=["referrals","games","login_days","xp"].includes(String(b.requirement_type))?String(b.requirement_type):"games";
      const requirementValue=Math.floor(Number(b.requirement_value));
      const rewardType=["xp","coins","gems","balance"].includes(String(b.reward_type))?String(b.reward_type):"coins";
      const rewardValue=Math.floor(Number(b.reward_value));
      const enabled=b.enabled===false||b.enabled==="0"?0:1;

      if(!/^[A-Z0-9_-]{2,50}$/.test(code)||!title||!description)
        return json({ok:false,error:"Dados da missão inválidos."},400,cors);
      if(!Number.isInteger(requirementValue)||requirementValue<1)
        return json({ok:false,error:"Requisito inválido."},400,cors);
      if(!Number.isInteger(rewardValue)||rewardValue<1)
        return json({ok:false,error:"Recompensa inválida."},400,cors);

      try{
        await env.DB.prepare(`
          INSERT INTO missions(code,title,description,period,requirement_type,requirement_value,reward_type,reward_value,enabled)
          VALUES(?,?,?,?,?,?,?,?,?)
        `).bind(code,title,description,period,requirementType,requirementValue,rewardType,rewardValue,enabled).run();
        await env.DB.prepare(`
          INSERT INTO audit_logs(actor_user_id,action,target_user_id,details)
          VALUES(?,?,?,?)
        `).bind(id,"create_mission",id,JSON.stringify({code})).run();
        return json({ok:true,message:"Missão criada."},200,cors);
      }catch(e){
        return json({ok:false,error:"Código de missão já existe."},409,cors);
      }
    }

    if(url.pathname.match(/^\/api\/admin\/missions\/\d+$/) && request.method==="PATCH"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const missionId=Number(url.pathname.split("/").pop());
      const b=await request.json();
      const enabled=b.enabled===false||b.enabled==="0"?0:1;
      const r=await env.DB.prepare("UPDATE missions SET enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(enabled,missionId).run();
      if(!r.meta.changes)return json({ok:false,error:"Missão não encontrada."},404,cors);
      return json({ok:true,message:"Missão atualizada."},200,cors);
    }

    if(url.pathname==="/api/progression" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      await unlockAchievements(env,id);
      const user=await env.DB.prepare("SELECT xp FROM users WHERE id=?").bind(id).first();
      const level=await getUserLevel(env,user?.xp||0);
      const achievements=await env.DB.prepare(`
        SELECT a.id,a.code,a.title,a.description,a.icon,a.requirement_type,a.requirement_value,
               a.reward_type,a.reward_value,ua.unlocked_at
        FROM achievements a
        LEFT JOIN user_achievements ua ON ua.achievement_id=a.id AND ua.user_id=?
        WHERE a.enabled=1 ORDER BY a.requirement_type,a.requirement_value
      `).bind(id).all();
      return json({ok:true,xp:Number(user?.xp||0),level,achievements:achievements.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/levels" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const levels=await env.DB.prepare("SELECT * FROM level_settings ORDER BY level").all();
      const achievements=await env.DB.prepare("SELECT * FROM achievements ORDER BY id").all();
      return json({ok:true,levels:levels.results||[],achievements:achievements.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/levels" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json();
      const level=Math.floor(Number(b.level)),xp=Math.floor(Number(b.xp_required));
      const title=String(b.title||"").trim().slice(0,80);
      if(!Number.isInteger(level)||level<1||level>100||!Number.isInteger(xp)||xp<0||!title)return json({ok:false,error:"Dados do nível inválidos."},400,cors);
      await env.DB.prepare(`
        INSERT INTO level_settings(level,xp_required,title) VALUES(?,?,?)
        ON CONFLICT(level) DO UPDATE SET xp_required=excluded.xp_required,title=excluded.title,updated_at=CURRENT_TIMESTAMP
      `).bind(level,xp,title).run();
      await env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)").bind(id,"update_level",id,JSON.stringify({level,xp,title})).run();
      return json({ok:true,message:"Nível salvo."},200,cors);
    }

    if(url.pathname==="/api/admin/achievements" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json();
      const code=String(b.code||"").trim().toUpperCase().replace(/\s+/g,"").slice(0,50);
      const title=String(b.title||"").trim().slice(0,100);
      const description=String(b.description||"").trim().slice(0,300);
      const icon=String(b.icon||"🏆").slice(0,8);
      const type=["referrals","xp"].includes(String(b.requirement_type))?String(b.requirement_type):"xp";
      const req=Math.floor(Number(b.requirement_value));
      const rewardType=["none","balance","coins","gems"].includes(String(b.reward_type))?String(b.reward_type):"none";
      const reward=Math.floor(Number(b.reward_value||0));
      if(!/^[A-Z0-9_-]{2,50}$/.test(code)||!title||!description||!Number.isInteger(req)||req<1||!Number.isInteger(reward)||reward<0)return json({ok:false,error:"Dados da conquista inválidos."},400,cors);
      try{
        await env.DB.prepare(`
          INSERT INTO achievements(code,title,description,icon,requirement_type,requirement_value,reward_type,reward_value)
          VALUES(?,?,?,?,?,?,?,?)
        `).bind(code,title,description,icon,type,req,rewardType,reward).run();
        await env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)").bind(id,"create_achievement",id,JSON.stringify({code})).run();
        return json({ok:true,message:"Conquista criada."},200,cors);
      }catch(e){return json({ok:false,error:"Código de conquista já existe."},409,cors)}
    }

    if(url.pathname.match(/^\/api\/admin\/achievements\/\d+\/toggle$/) && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const achievementId=Number(url.pathname.split("/")[4]);
      const b=await request.json();
      const enabled=b.enabled===false||b.enabled==="0"?0:1;
      const r=await env.DB.prepare("UPDATE achievements SET enabled=? WHERE id=?").bind(enabled,achievementId).run();
      if(!r.meta.changes)return json({ok:false,error:"Conquista não encontrada."},404,cors);
      return json({ok:true,message:"Conquista atualizada."},200,cors);
    }

    if(url.pathname==="/api/dashboard" && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const user=await env.DB.prepare(`
        SELECT id,name,plan,vip_until,balance_cents,coins,gems,xp,referral_code,status,created_at
        FROM users WHERE id=?`).bind(id).first();
      if(!user||user.status!=="active")return json({ok:false,error:"Conta indisponível."},403,cors);

      const referrals=await env.DB.prepare(`
        SELECT COUNT(*) c FROM referral_events WHERE referrer_id=? AND status='approved'`
      ).bind(id).first().catch(()=>({c:0}));
      const pending=await env.DB.prepare(`
        SELECT COUNT(*) c FROM referral_events WHERE referrer_id=? AND status='pending'`
      ).bind(id).first().catch(()=>({c:0}));
      const games=await env.DB.prepare(`
        SELECT game,COUNT(*) c FROM game_plays
        WHERE user_id=? AND created_at>=datetime('now','start of day') GROUP BY game`
      ).bind(id).all().catch(()=>({results:[]}));
      const rank=await env.DB.prepare(`
        SELECT COUNT(*)+1 position FROM users
        WHERE status='active' AND xp>(SELECT xp FROM users WHERE id=?)`
      ).bind(id).first().catch(()=>({position:null}));

      const progression=await getUserLevel(env,user.xp);
      await unlockAchievements(env,id);
      return json({ok:true,user,progression,stats:{
        referrals:Number(referrals?.c||0),
        pending_referrals:Number(pending?.c||0),
        ranking_position:rank?.position?Number(rank.position):null,
        today_games:games.results||[]
      }},200,cors);
    }

    if(url.pathname==="/api/ranking" && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const setting=await env.DB.prepare("SELECT key,value FROM ranking_settings").all();
      const cfg=Object.fromEntries((setting.results||[]).map(x=>[x.key,x.value]));
      if(cfg.enabled!=="1")return json({ok:false,error:"Ranking desativado."},503,cors);
      const rows=await env.DB.prepare(`
        SELECT id,name,plan,xp,coins,gems,referral_code
        FROM users WHERE status='active'
        ORDER BY xp DESC, id ASC LIMIT 100`).all();
      const list=(rows.results||[]).map((u,i)=>({...u,position:i+1}));
      return json({ok:true,settings:cfg,ranking:list},200,cors);
    }

    if(url.pathname==="/api/admin/ranking/settings" && request.method==="POST") {
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json();
      const enabled=b.enabled===false||b.enabled==="0"?"0":"1";
      const metric=["xp","referrals","coins","gems"].includes(String(b.metric))?String(b.metric):"xp";
      const period=["all","month","week"].includes(String(b.period))?String(b.period):"all";
      await env.DB.batch([
        env.DB.prepare("INSERT INTO ranking_settings(key,value,updated_at,updated_by) VALUES('enabled',?,CURRENT_TIMESTAMP,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP,updated_by=excluded.updated_by").bind(enabled,id),
        env.DB.prepare("INSERT INTO ranking_settings(key,value,updated_at,updated_by) VALUES('metric',?,CURRENT_TIMESTAMP,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP,updated_by=excluded.updated_by").bind(metric,id),
        env.DB.prepare("INSERT INTO ranking_settings(key,value,updated_at,updated_by) VALUES('period',?,CURRENT_TIMESTAMP,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP,updated_by=excluded.updated_by").bind(period,id)
      ]);
      return json({ok:true,message:"Ranking atualizado."},200,cors);
    }


    if(url.pathname==="/api/partners" && request.method==="GET"){
      const rows=await env.DB.prepare(`
        SELECT id,name,description,logo_url,banner_url,target_url,placement
        FROM partners
        WHERE status='active'
          AND (starts_at IS NULL OR starts_at<=CURRENT_TIMESTAMP)
          AND (ends_at IS NULL OR ends_at>=CURRENT_TIMESTAMP)
        ORDER BY id DESC LIMIT 20
      `).all();
      return json({ok:true,partners:rows.results||[]},200,cors);
    }

    if(url.pathname.match(/^\/api\/partners\/\d+\/impression$/) && request.method==="POST"){
      const partnerId=Number(url.pathname.split("/")[3]);
      if(!Number.isInteger(partnerId))return json({ok:false,error:"Parceiro inválido."},400,cors);
      const id=await readSession(request,env);
      await env.DB.batch([
        env.DB.prepare("UPDATE partners SET impressions=impressions+1,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='active'").bind(partnerId),
        env.DB.prepare("INSERT INTO partner_events(partner_id,user_id,event_type) VALUES(?,?,?)").bind(partnerId,id||null,"impression")
      ]);
      return json({ok:true},200,cors);
    }

    if(url.pathname.match(/^\/api\/partners\/\d+\/click$/) && request.method==="POST"){
      const partnerId=Number(url.pathname.split("/")[3]);
      if(!Number.isInteger(partnerId))return json({ok:false,error:"Parceiro inválido."},400,cors);
      const id=await readSession(request,env);
      const partner=await env.DB.prepare(`
        SELECT target_url FROM partners WHERE id=? AND status='active'
          AND (starts_at IS NULL OR starts_at<=CURRENT_TIMESTAMP)
          AND (ends_at IS NULL OR ends_at>=CURRENT_TIMESTAMP)
      `).bind(partnerId).first();
      if(!partner)return json({ok:false,error:"Oferta indisponível."},404,cors);
      await env.DB.batch([
        env.DB.prepare("UPDATE partners SET clicks=clicks+1,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(partnerId),
        env.DB.prepare("INSERT INTO partner_events(partner_id,user_id,event_type) VALUES(?,?,?)").bind(partnerId,id||null,"click")
      ]);
      return json({ok:true,url:partner.target_url},200,cors);
    }

    if(url.pathname==="/api/admin/partners" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const rows=await env.DB.prepare("SELECT * FROM partners ORDER BY id DESC").all();
      return json({ok:true,partners:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/partners" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json();
      const name=String(b.name||"").trim().slice(0,120);
      const description=String(b.description||"").trim().slice(0,500);
      const logo=String(b.logo_url||"").trim().slice(0,1000);
      const banner=String(b.banner_url||"").trim().slice(0,1000);
      const target=String(b.target_url||"").trim().slice(0,1500);
      const placement=["dashboard","home","ranking","games"].includes(String(b.placement))?String(b.placement):"dashboard";
      if(name.length<2||!/^https?:\/\//i.test(target))return json({ok:false,error:"Nome e URL válida são obrigatórios."},400,cors);
      const result=await env.DB.prepare(`
        INSERT INTO partners(name,description,logo_url,banner_url,target_url,placement,status,starts_at,ends_at)
        VALUES(?,?,?,?,?,?,?,?,?)
      `).bind(name,description,logo,banner,target,placement,"active",b.starts_at||null,b.ends_at||null).run();
      await env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)")
        .bind(id,"create_partner",id,JSON.stringify({partner_id:result.meta.last_row_id,name})).run();
      return json({ok:true,message:"Parceiro criado.",partner_id:result.meta.last_row_id},200,cors);
    }

    if(url.pathname.match(/^\/api\/admin\/partners\/\d+$/) && request.method==="PATCH"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const partnerId=Number(url.pathname.split("/").pop());
      const b=await request.json();
      const allowed=["name","description","logo_url","banner_url","target_url","placement","status","starts_at","ends_at"];
      const current=await env.DB.prepare("SELECT * FROM partners WHERE id=?").bind(partnerId).first();
      if(!current)return json({ok:false,error:"Parceiro não encontrado."},404,cors);
      const values={...current,...b};
      if(!/^https?:\/\//i.test(String(values.target_url||"")))return json({ok:false,error:"URL inválida."},400,cors);
      const placement=["dashboard","home","ranking","games"].includes(String(values.placement))?values.placement:"dashboard";
      const status=["active","paused","ended"].includes(String(values.status))?values.status:"paused";
      await env.DB.prepare(`
        UPDATE partners SET name=?,description=?,logo_url=?,banner_url=?,target_url=?,placement=?,status=?,starts_at=?,ends_at=?,updated_at=CURRENT_TIMESTAMP
        WHERE id=?
      `).bind(String(values.name||"").slice(0,120),String(values.description||"").slice(0,500),String(values.logo_url||"").slice(0,1000),String(values.banner_url||"").slice(0,1000),String(values.target_url),placement,status,values.starts_at||null,values.ends_at||null,partnerId).run();
      await env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)")
        .bind(id,"update_partner",id,JSON.stringify({partner_id:partnerId})).run();
      return json({ok:true,message:"Parceiro atualizado."},200,cors);
    }

    if(url.pathname.match(/^\/api\/admin\/partners\/\d+\/stats$/) && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const partnerId=Number(url.pathname.split("/")[4]);
      const p=await env.DB.prepare("SELECT id,name,impressions,clicks FROM partners WHERE id=?").bind(partnerId).first();
      if(!p)return json({ok:false,error:"Parceiro não encontrado."},404,cors);
      const events=await env.DB.prepare(`
        SELECT date(created_at) day,
        SUM(CASE WHEN event_type='impression' THEN 1 ELSE 0 END) impressions,
        SUM(CASE WHEN event_type='click' THEN 1 ELSE 0 END) clicks
        FROM partner_events WHERE partner_id=? GROUP BY date(created_at) ORDER BY day DESC LIMIT 30
      `).bind(partnerId).all();
      return json({ok:true,partner:p,days:events.results||[]},200,cors);
    }


    if(url.pathname==="/api/promos/redeem" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      const b=await request.json();
      const code=String(b.code||"").trim().toUpperCase().replace(/\s+/g,"").slice(0,50);
      if(!code)return json({ok:false,error:"Digite o código promocional."},400,cors);

      const promo=await env.DB.prepare(`
        SELECT * FROM promo_codes WHERE code=? AND status='active'
        AND (starts_at IS NULL OR starts_at<=CURRENT_TIMESTAMP)
        AND (ends_at IS NULL OR ends_at>=CURRENT_TIMESTAMP)
      `).bind(code).first();
      if(!promo)return json({ok:false,error:"Código inválido, expirado ou indisponível."},404,cors);
      if(Number(promo.redemption_count)>=Number(promo.max_redemptions))
        return json({ok:false,error:"Esse código já atingiu o limite de resgates."},409,cors);

      const used=await env.DB.prepare("SELECT id FROM promo_redemptions WHERE promo_id=? AND user_id=?").bind(promo.id,id).first();
      if(used)return json({ok:false,error:"Você já utilizou esse código."},409,cors);

      const benefit=Number(promo.benefit_value);
      const stmts=[
        env.DB.prepare(`
          INSERT INTO promo_redemptions(promo_id,user_id,benefit_type,benefit_value)
          VALUES(?,?,?,?)
        `).bind(promo.id,id,promo.benefit_type,benefit),
        env.DB.prepare("UPDATE promo_codes SET redemption_count=redemption_count+1,updated_at=CURRENT_TIMESTAMP WHERE id=? AND redemption_count<max_redemptions").bind(promo.id)
      ];

      let notification="";
      if(promo.benefit_type==="vip_days"){
        stmts.push(env.DB.prepare(`
          UPDATE users SET plan='VIP',
          vip_until=CASE
            WHEN vip_until IS NULL OR vip_until<CURRENT_TIMESTAMP THEN datetime('now','+'||?||' days')
            ELSE datetime(vip_until,'+'||?||' days')
          END,updated_at=CURRENT_TIMESTAMP WHERE id=?
        `).bind(benefit,benefit,id));
        notification=`Seu VIP foi ativado/estendido por ${benefit} dia(s).`;
      }else if(promo.benefit_type==="balance_cents"){
        stmts.push(env.DB.prepare("UPDATE users SET balance_cents=balance_cents+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(benefit,id));
        notification=`Você recebeu R$ ${(benefit/100).toFixed(2).replace(".",",")} de saldo.`;
      }else if(promo.benefit_type==="coins"){
        stmts.push(env.DB.prepare("UPDATE users SET coins=COALESCE(coins,0)+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(benefit,id));
        notification=`Você recebeu ${benefit} Coins.`;
      }else{
        stmts.push(env.DB.prepare("UPDATE users SET gems=COALESCE(gems,0)+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(benefit,id));
        notification=`Você recebeu ${benefit} Gemas.`;
      }
      await env.DB.batch(stmts);
      await createNotification(env,id,"system","🎁 Código resgatado",notification);
      return json({ok:true,message:"Código resgatado com sucesso!",benefit_type:promo.benefit_type,benefit_value:benefit},200,cors);
    }

    if(url.pathname==="/api/admin/promos" && request.method==="GET"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const rows=await env.DB.prepare("SELECT * FROM promo_codes ORDER BY id DESC LIMIT 300").all();
      return json({ok:true,promos:rows.results||[]},200,cors);
    }

    if(url.pathname==="/api/admin/promos" && request.method==="POST"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const b=await request.json();
      let code=String(b.code||"").trim().toUpperCase().replace(/\s+/g,"").slice(0,50);
      const benefitType=["vip_days","balance_cents","coins","gems"].includes(String(b.benefit_type))?String(b.benefit_type):"vip_days";
      const value=Math.floor(Number(b.benefit_value));
      const max=Math.floor(Number(b.max_redemptions));
      const description=String(b.description||"").trim().slice(0,300);
      if(!/^[A-Z0-9_-]{3,50}$/.test(code))return json({ok:false,error:"Código inválido. Use letras, números, _ ou -."},400,cors);
      if(!Number.isSafeInteger(value)||value<=0)return json({ok:false,error:"Benefício inválido."},400,cors);
      if(!Number.isSafeInteger(max)||max<1||max>1000000)return json({ok:false,error:"Quantidade de resgates inválida."},400,cors);
      if(benefitType==="balance_cents" && value>10000000)return json({ok:false,error:"Saldo máximo por código: R$ 100.000,00."},400,cors);
      try{
        const result=await env.DB.prepare(`
          INSERT INTO promo_codes(code,description,benefit_type,benefit_value,max_redemptions,starts_at,ends_at,created_by)
          VALUES(?,?,?,?,?,?,?,?)
        `).bind(code,description,benefitType,value,max,b.starts_at||null,b.ends_at||null,id).run();
        await env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)")
          .bind(id,"create_promo_code",id,JSON.stringify({promo_id:result.meta.last_row_id,code,benefitType,value,max})).run();
        return json({ok:true,message:"Código promocional criado.",promo_id:result.meta.last_row_id},200,cors);
      }catch(e){
        return json({ok:false,error:"Esse código já existe."},409,cors);
      }
    }

    if(url.pathname.match(/^\/api\/admin\/promos\/\d+$/) && request.method==="PATCH"){
      const id=await readSession(request,env);
      if(!id)return json({ok:false,error:"Não autenticado."},401,cors);
      if(Number(env.ADMIN_USER_ID||0)!==id)return json({ok:false,error:"Acesso negado."},403,cors);
      const promoId=Number(url.pathname.split("/").pop());
      const b=await request.json();
      if(!["active","paused","ended"].includes(String(b.status)))return json({ok:false,error:"Status inválido."},400,cors);
      const r=await env.DB.prepare("UPDATE promo_codes SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(String(b.status),promoId).run();
      if(!r.meta.changes)return json({ok:false,error:"Código não encontrado."},404,cors);
      await env.DB.prepare("INSERT INTO audit_logs(actor_user_id,action,target_user_id,details) VALUES(?,?,?,?)")
        .bind(id,"update_promo_code",id,JSON.stringify({promo_id:promoId,status:b.status})).run();
      return json({ok:true,message:"Código atualizado."},200,cors);
    }

    if(url.pathname==="/api/me" && request.method==="GET") {
      const id=await readSession(request,env);
      if(!id) return json({ok:false,error:"Não autenticado."},401,cors);
      const user=await env.DB.prepare(
        "SELECT id,name,email,referral_code,plan,vip_until,balance_cents,coins,gems,xp,status,created_at FROM users WHERE id=?"
      ).bind(id).first();
      if(!user) return json({ok:false,error:"Usuário não encontrado."},404,cors);
      if(user.status==="banned") return json({ok:false,error:"Conta bloqueada."},403,{...cors,"Set-Cookie":cookie("",0)});
      return json({ok:true,user},200,cors);
    }

    return json({ok:false,error:"Rota não encontrada."},404,cors);
  } catch(e) {
    console.error(e);
    return json({ok:false,error:"Erro interno do servidor."},500,cors);
  }
}

export default { async fetch(request,env) { return api(request,env); } };
