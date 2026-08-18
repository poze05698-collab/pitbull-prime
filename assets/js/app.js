async function apiMe(){
  const r=await fetch('/api/me',{credentials:'include'});
  if(!r.ok){if(location.pathname.endsWith('dashboard.html')) location.href='login.html';return null;}
  const d=await r.json();return d.user;
}
async function loadDashboard(){
  const u=await apiMe(); if(!u)return;
  const name=document.getElementById('user'); if(name)name.textContent=u.name;
  const plan=document.querySelector('.badge'); if(plan)plan.textContent=u.plan==='VIP'?'💎 CONTA VIP':'🆓 CONTA FREE';
  const stats=document.querySelectorAll('.stats strong');
  if(stats[0])stats[0].textContent=`R$ ${(Number(u.balance_cents||0)/100).toFixed(2).replace('.',',')}`;
  if(stats[1])stats[1].textContent=u.coins;
  if(stats[2])stats[2].textContent=u.gems;
  if(stats[3])stats[3].textContent=u.xp;
}
async function logout(){
  await fetch('/api/logout',{method:'POST',credentials:'include'});
  location.href='index.html';
}
document.addEventListener('DOMContentLoaded',loadDashboard);

async function loadReferrals(){
  const box=document.getElementById('refBox'); if(!box)return;
  box.textContent='Carregando...';
  try{
    const r=await fetch('/api/referrals',{credentials:'include'});
    const d=await r.json();
    if(!r.ok) throw new Error(d.error||'Erro');
    box.innerHTML=`<div class="ref-box"><b>🔗 Seu link</b><input readonly value="${d.referral_link}" onclick="this.select()"><p>👥 ${d.totals.total} • ✅ ${d.totals.approved} • ⏳ ${d.totals.pending} • ❌ ${d.totals.rejected}</p><strong>💰 R$ ${(d.totals.earned_cents/100).toFixed(2).replace('.',',')}</strong></div>`;
  }catch(e){box.textContent='❌ '+e.message;}
}

async function loadGames(){
  const r=await fetch('/api/games/status',{credentials:'include'}); const d=await r.json();
  if(!r.ok)return;
  const rs=document.getElementById('rouletteStatus'),ss=document.getElementById('scratchStatus');
  if(rs)rs.textContent=`${d.remaining.roulette} giro(s) restante(s) hoje`;
  if(ss)ss.textContent=`${d.remaining.scratch} raspadinha(s) restante(s) hoje`;
}
async function play(game){
  const r=await fetch('/api/games/'+game,{method:'POST',credentials:'include'});
  const d=await r.json();
  const box=document.getElementById('gameResult');
  if(!r.ok){if(box)box.textContent='❌ '+(d.error||'Não foi possível jogar.');loadGames();return;}
  if(box)box.textContent=`🎉 Você ganhou: ${d.prize.label}`;
  loadGames();loadDashboard();
}
document.addEventListener('DOMContentLoaded',()=>{loadDashboard();loadGames()});

async function showVip(){
  const panel=document.getElementById('vipPanel'); if(!panel)return;
  panel.hidden=false;
  const r=await fetch('/api/vip',{credentials:'include'});const d=await r.json();
  const info=document.getElementById('vipInfo');
  if(!r.ok){info.textContent='❌ '+(d.error||'Erro');return}
  const active=d.plan==='VIP' && d.vip_until && d.vip_until>new Date().toISOString();
  document.getElementById('vipStatus').textContent=active?`VIP ativo até ${new Date(d.vip_until).toLocaleDateString('pt-BR')}`:`R$ ${(d.price_cents/100).toFixed(2).replace('.',',')} / ${d.duration_days} dias`;
  info.innerHTML=`<b>${active?'Seu VIP está ativo.':'Plano VIP'}</b><br><br>💰 R$ ${(d.price_cents/100).toFixed(2).replace('.',',')} / ${d.duration_days} dias<br><br>🎰 2 giros de roleta por dia<br>🎫 2 raspadinhas por dia<br>🍀 Mais benefícios conforme as regras da plataforma<br><br>🆘 Aquisição: fale com o suporte.`;
}
function closeVip(){const p=document.getElementById('vipPanel');if(p)p.hidden=true}
async function redeemVip(){
  const code=prompt('Digite seu código VIP:'); if(!code)return;
  const r=await fetch('/api/vip/redeem',{method:'POST',credentials:'include',headers:{'content-type':'application/json'},body:JSON.stringify({code})});
  const d=await r.json();
  if(!r.ok){alert('❌ '+(d.error||'Não foi possível resgatar.'));return}
  alert('✅ VIP ativado até '+new Date(d.vip_until).toLocaleDateString('pt-BR'));closeVip();loadDashboard();loadGames();
}

function moneyBR(c){return "R$ "+(Number(c||0)/100).toFixed(2).replace(".",",")}
async function loadWallet(){
  const info=document.getElementById('walletInfo');if(!info)return;
  try{
    const [w,wd]=await Promise.all([
      fetch('/api/wallet',{credentials:'include'}).then(r=>r.json()),
      fetch('/api/withdrawals',{credentials:'include'}).then(r=>r.json())
    ]);
    if(!w.ok)throw new Error(w.error||'Erro');
    info.textContent=`Saldo disponível: ${moneyBR(w.balance_cents)} • Pendente: ${moneyBR(w.pending_withdrawal_cents)}`;
    const box=document.getElementById('withdrawals');
    box.innerHTML=(wd.withdrawals||[]).map(x=>`<div class="ref-box">💸 #${x.id} • ${moneyBR(x.amount_cents)} • ${x.status}<br><small>${new Date(x.created_at.replace(' ','T')+'Z').toLocaleString('pt-BR')}</small></div>`).join('');
  }catch(e){info.textContent='❌ '+e.message}
}
async function requestWithdrawal(){
  const value=prompt('Valor do saque em R$ (mínimo configurado pelo admin):');if(value===null)return;
  const n=Number(value.replace(',','.'));if(!Number.isFinite(n)||n<=0){alert('Valor inválido.');return}
  const pix=prompt('Digite sua chave PIX:');if(!pix)return;
  const type=prompt('Tipo da chave (cpf, cnpj, email, phone, random ou manual):','manual')||'manual';
  const r=await fetch('/api/withdrawals',{method:'POST',credentials:'include',headers:{'content-type':'application/json'},body:JSON.stringify({amount_cents:Math.round(n*100),pix_key:pix,pix_type:type})});
  const d=await r.json();alert(r.ok?'✅ '+d.message:'❌ '+(d.error||'Erro'));loadWallet();loadDashboard();
}
document.addEventListener('DOMContentLoaded',loadWallet);

function ticketStatus(s){return s==="open"?"🟢 Aberto":s==="pending"?"🟡 Aguardando":"⚪ Fechado"}
async function loadTickets(){
 const box=document.getElementById("tickets");if(!box)return;
 try{const d=await fetch("/api/tickets",{credentials:"include"}).then(r=>r.json());
  if(!d.ok)throw new Error(d.error||"Erro");
  box.innerHTML=(d.tickets||[]).map(t=>`<div class="ref-box"><b>#${t.id} ${escText(t.subject)}</b><br>${ticketStatus(t.status)} • ${t.priority}<br><button class="btn" onclick="openTicket(${t.id})">Abrir conversa</button></div>`).join("")||"<p>Nenhum chamado.</p>";
 }catch(e){box.textContent="❌ "+e.message}
}
function escText(v){return String(v??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[m]))}
async function newTicket(){
 const subject=prompt("Assunto do chamado:");if(!subject)return;
 const message=prompt("Explique o que você precisa:");if(!message)return;
 const r=await fetch("/api/tickets",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:JSON.stringify({subject,message,priority:"normal"})});
 const d=await r.json();alert(r.ok?"✅ "+d.message:"❌ "+(d.error||"Erro"));loadTickets();
}
async function openTicket(id){
 const d=await fetch("/api/tickets/"+id,{credentials:"include"}).then(r=>r.json());
 if(!d.ok){alert("❌ "+d.error);return}
 let text=`#${id} — ${d.ticket.subject}\n\n`;
 for(const m of d.messages)text+=`${m.sender_type==="admin"?"👑 Admin":"👤 Você"}: ${m.message}\n\n`;
 alert(text);
 if(d.ticket.status!=="closed"){
  const msg=prompt("Enviar nova mensagem (Cancelar para fechar):");
  if(msg){
   const r=await fetch("/api/tickets/"+id+"/messages",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:JSON.stringify({message:msg})});
   const x=await r.json();alert(r.ok?"✅ "+x.message:"❌ "+(x.error||"Erro"));loadTickets();
  }
 }
}
document.addEventListener("DOMContentLoaded",loadTickets);

async function checkPlatformStatus(){
  try{
    const r=await fetch("/api/platform/status",{credentials:"include"});
    const d=await r.json();
    if(!d.ok)return;
    let bar=document.getElementById("maintenanceBar");
    if(d.maintenance){
      if(!bar){bar=document.createElement("div");bar.id="maintenanceBar";document.body.prepend(bar)}
      bar.textContent="🛠️ "+d.settings.maintenance_message;
      bar.style.cssText="position:fixed;top:0;left:0;right:0;z-index:9999;background:#5a3510;color:#fff;padding:11px;text-align:center;font-weight:700";
      document.body.style.paddingTop="44px";
    }else if(bar){bar.remove();document.body.style.paddingTop=""}
  }catch(e){}
}
document.addEventListener("DOMContentLoaded",checkPlatformStatus);

async function loadNotifications(){
 const box=document.getElementById("notifications");if(!box)return;
 try{
  const d=await fetch("/api/notifications",{credentials:"include"}).then(r=>r.json());
  if(!d.ok)throw new Error(d.error||"Erro");
  const badge=document.getElementById("notifBadge");
  if(badge)badge.textContent=d.unread?`(${d.unread})`:"";
  box.innerHTML=(d.notifications||[]).map(n=>`<div class="ref-box ${n.read_at?"":"unread"}" onclick="readNotification(${n.id})"><b>${escText(n.title)}</b><br>${escText(n.message)}<small>${new Date(n.created_at.replace(' ','T')+'Z').toLocaleString('pt-BR')}</small></div>`).join("")||"<p>Nenhuma notificação.</p>";
 }catch(e){box.textContent="❌ "+e.message}
}
async function readNotification(id){
 await fetch("/api/notifications/read",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:JSON.stringify({id})});
 loadNotifications();
}
async function markAllNotifications(){
 await fetch("/api/notifications/read",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:JSON.stringify({all:true})});
 loadNotifications();
}
document.addEventListener("DOMContentLoaded",loadNotifications);

async function loadOverview(){
 const box=document.getElementById("overviewStats");if(!box)return;
 try{
  const d=await fetch("/api/dashboard",{credentials:"include"}).then(r=>r.json());
  if(!d.ok)throw new Error(d.error||"Erro");
  const u=d.user,s=d.stats;
  box.innerHTML=`<div class="stats"><div>💰 Saldo<strong>${moneyBR(u.balance_cents)}</strong></div><div>🪙 Coins<strong>${u.coins||0}</strong></div><div>💎 Gemas<strong>${u.gems||0}</strong></div><div>⭐ XP<strong>${u.xp||0}</strong></div><div>👥 Indicados<strong>${s.referrals}</strong></div><div>⏳ Pendentes<strong>${s.pending_referrals}</strong></div></div>`;
  const rank=document.getElementById("myRank");if(rank)rank.innerHTML=`🏆 Sua posição: <b>${s.ranking_position||"—"}</b>`;
 }catch(e){box.textContent="❌ "+e.message}
}
async function loadRanking(){
 const box=document.getElementById("rankingList");if(!box)return;
 try{
  const d=await fetch("/api/ranking",{credentials:"include"}).then(r=>r.json());
  if(!d.ok)throw new Error(d.error||"Erro");
  box.innerHTML=d.ranking.map(u=>`<div class="user-row"><div><b>${u.position<=3?["🥇","🥈","🥉"][u.position-1]:"🏅"} #${u.position} ${escText(u.name)}</b><small>${u.plan==="VIP"?"💎 VIP":"FREE"} • ⭐ ${u.xp} XP • 👥 ${u.referral_code}</small></div><strong>${u.xp} XP</strong></div>`).join("")||"Nenhum participante.";
 }catch(e){box.textContent="❌ "+e.message}
}
document.addEventListener("DOMContentLoaded",()=>{loadOverview();loadRanking()});

async function loadReferralSummary(){
 const box=document.getElementById("referralBox");if(!box)return;
 try{
  const d=await fetch("/api/referrals/summary",{credentials:"include"}).then(r=>r.json());
  if(!d.ok)throw new Error(d.error||"Erro");
  box.innerHTML=`<p><b>Seu código:</b> ${escText(d.referral_code)}</p><p><b>Seu link:</b></p><input readonly value="${escText(d.referral_link)}" style="width:100%;box-sizing:border-box"><div class="stats"><div>👥 Total<strong>${d.stats.total}</strong></div><div>✅ Aprovadas<strong>${d.stats.approved}</strong></div><div>⏳ Pendentes<strong>${d.stats.pending}</strong></div><div>💰 Ganho<strong>${moneyBR(d.stats.earned_cents)}</strong></div></div>`;
 }catch(e){box.textContent="❌ "+e.message}
}
document.addEventListener("DOMContentLoaded",loadReferralSummary);

async function loadPartners(){
 const box=document.getElementById("partners");if(!box)return;
 try{
  const d=await fetch("/api/partners",{credentials:"include"}).then(r=>r.json());
  if(!d.ok)throw new Error(d.error||"Erro");
  box.innerHTML=(d.partners||[]).map(p=>`<div class="partner-card">${p.banner_url?`<img src="${escText(p.banner_url)}" alt="${escText(p.name)}">`:""}<div><b>${escText(p.name)}</b><p>${escText(p.description||"")}</p><button class="btn" onclick="openPartner(${p.id})">Ver oferta</button></div></div>`).join("")||"<p>Nenhum parceiro ativo no momento.</p>";
  for(const p of (d.partners||[])) fetch("/api/partners/"+p.id+"/impression",{method:"POST",credentials:"include"});
 }catch(e){box.textContent="❌ "+e.message}
}
async function openPartner(id){
 try{
  const d=await fetch("/api/partners/"+id+"/click",{method:"POST",credentials:"include"}).then(r=>r.json());
  if(!d.ok)return alert("❌ "+d.error);
  window.open(d.url,"_blank","noopener,noreferrer");
 }catch(e){alert("❌ Não foi possível abrir a oferta.")}
}
document.addEventListener("DOMContentLoaded",loadPartners);

async function redeemPromo(){
 const el=document.getElementById("promoCode");const code=el.value.trim();if(!code)return msg("❌ Digite o código.");
 try{
  const r=await fetch("/api/promos/redeem",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:JSON.stringify({code})});
  const d=await r.json();msg(r.ok?"✅ "+d.message:"❌ "+(d.error||"Erro"));if(r.ok){el.value="";loadOverview();loadNotifications()}
 }catch(e){msg("❌ Não foi possível resgatar agora.")}
}

async function loadProgression(){
 const box=document.getElementById("progression");if(!box)return;
 try{
  const d=await fetch("/api/progression",{credentials:"include"}).then(r=>r.json());
  if(!d.ok)throw new Error(d.error||"Erro");
  const l=d.level;
  box.innerHTML=`<div class="level-card"><b>🏆 Nível ${l.level} — ${escText(l.title)}</b><p>⭐ ${d.xp} XP ${l.next_level?`• Próximo: nível ${l.next_level} em ${l.next_xp} XP`:"• Nível máximo atual"}</p><div class="progress-track"><div class="progress-fill" style="width:${l.progress_to_next}%"></div></div></div><div class="achievement-grid">${d.achievements.map(a=>`<div class="achievement ${a.unlocked_at?"unlocked":"locked"}"><span>${escText(a.icon)}</span><b>${escText(a.title)}</b><small>${escText(a.description)}</small><small>${a.unlocked_at?"✅ Desbloqueada":"🔒 Ainda bloqueada"}</small></div>`).join("")}</div>`;
 }catch(e){box.textContent="❌ "+e.message}
}
document.addEventListener("DOMContentLoaded",loadProgression);

async function claimDailyXP(){
 try{
  const r=await fetch("/api/daily-login",{method:"POST",credentials:"include"});
  const d=await r.json();
  msg(r.ok?"✅ "+d.message:"❌ "+(d.error||"Erro"));
  const el=document.getElementById("dailyXP");
  if(el)el.textContent=d.awarded>0?`+${d.awarded} XP recebido hoje.`:"O bônus de hoje já foi processado.";
  if(r.ok){loadOverview();loadProgression();}
 }catch(e){msg("❌ Não foi possível processar o bônus agora.")}
}

async function loadMissions(){
 const box=document.getElementById("missions");if(!box)return;
 try{
  const d=await fetch("/api/missions",{credentials:"include"}).then(r=>r.json());
  if(!d.ok)throw new Error(d.error||"Erro");
  box.innerHTML=(d.missions||[]).map(m=>{
    const pct=Math.min(100,(Number(m.progress)/Number(m.requirement_value))*100);
    const done=Number(m.progress)>=Number(m.requirement_value);
    return `<div class="mission-card"><div><b>🎯 ${escText(m.title)}</b><p>${escText(m.description)}</p><small>${m.progress}/${m.requirement_value} • recompensa: ${m.reward_value} ${escText(m.reward_type)}</small><div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div></div>${done&&!m.claimed_at?`<button class="btn" onclick="claimMission(${m.id})">🎁 Resgatar</button>`:m.claimed_at?"<span>✅ Resgatada</span>":""}</div>`;
  }).join("")||"Nenhuma missão disponível.";
 }catch(e){box.textContent="❌ "+e.message}
}
async function claimMission(id){
 try{
  const r=await fetch("/api/missions/"+id+"/claim",{method:"POST",credentials:"include"});
  const d=await r.json();msg(r.ok?"✅ "+d.message:"❌ "+(d.error||"Erro"));
  if(r.ok){loadMissions();loadOverview();loadProgression();}
 }catch(e){msg("❌ Não foi possível resgatar a missão.")}
}
document.addEventListener("DOMContentLoaded",loadMissions);

async function loadRanking(period="daily"){
 const box=document.getElementById("ranking");if(!box)return;
 try{
  const d=await fetch("/api/ranking?period="+period,{credentials:"include"}).then(r=>r.json());
  if(!d.ok)throw new Error(d.error||"Erro");
  const medals=["🥇","🥈","🥉"];
  box.innerHTML=`<div class="ranking-me">${d.me?`Sua posição: <b>#${d.me.position}</b> • ${d.me.score} XP`:"Você ainda não pontuou neste período."}</div>`+
   ((d.ranking||[]).slice(0,20).map(r=>`<div class="rank-row"><span>${medals[r.position-1]||"#"+r.position}</span><b>${escText(r.name||"Usuário")}</b><span>${r.score} XP</span></div>`).join("")||"<p>Nenhum participante ainda.</p>")+
   ((d.me&&d.rewards.some(x=>Number(x.position)===Number(d.me.position)))?`<button class="btn" onclick="claimRanking('${period}')">🎁 Resgatar prêmio</button>`:"");
 }catch(e){box.textContent="❌ "+e.message}
}
async function claimRanking(period){
 try{
  const r=await fetch("/api/ranking/claim",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:JSON.stringify({period})});
  const d=await r.json();msg(r.ok?"✅ "+d.message:"❌ "+(d.error||"Erro"));
  if(r.ok){loadRanking(period);loadOverview();}
 }catch(e){msg("❌ Não foi possível resgatar o prêmio.")}
}
document.addEventListener("DOMContentLoaded",()=>loadRanking("daily"));

function notificationIcon(type){
 const icons={success:"✅",reward:"🎁",vip:"👑",referral:"👥",mission:"🎯",ranking:"🏆",withdrawal:"💸",promo:"🎟️",security:"🔐",system:"🔔"};
 return icons[type]||"🔔";
}
async function loadNotifications(){
 const box=document.getElementById("notifications");if(!box)return;
 try{
  const d=await fetch("/api/notifications?limit=50",{credentials:"include"}).then(r=>r.json());
  if(!d.ok)throw new Error(d.error||"Erro");
  box.innerHTML=(d.notifications||[]).map(n=>`
    <div class="notification-card ${Number(n.is_read)?"read":"unread"}" id="notification-${n.id}">
      <div class="notification-icon">${notificationIcon(n.type)}</div>
      <div class="notification-body"><b>${escText(n.title)}</b><p>${escText(n.message)}</p><small>${escText(n.created_at)}</small></div>
      <div class="notification-actions">${!Number(n.is_read)?`<button class="btn" onclick="markNotification(${n.id})">✓</button>`:""}<button class="btn" onclick="deleteNotification(${n.id})">🗑️</button></div>
    </div>`).join("")||"<p>Nenhuma notificação.</p>";
 }catch(e){box.textContent="❌ "+e.message}
}
async function markNotification(id){
 try{
  const r=await fetch("/api/notifications/read",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:JSON.stringify({id})});
  if(r.ok)loadNotifications();
 }catch(e){}
}
async function markAllNotifications(){
 try{
  const r=await fetch("/api/notifications/read",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:"{}"});
  if(r.ok){msg("✅ Todas as notificações foram marcadas como lidas.");loadNotifications();}
 }catch(e){msg("❌ Não foi possível atualizar as notificações.")}
}
async function deleteNotification(id){
 try{
  const r=await fetch("/api/notifications/delete",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:JSON.stringify({id})});
  if(r.ok)loadNotifications();
 }catch(e){}
}
document.addEventListener("DOMContentLoaded",loadNotifications);

async function loadVIP(){
 const box=document.getElementById("vipInfo"),status=document.getElementById("vipStatus"),support=document.getElementById("vipSupport");
 if(!box)return;
 try{
  const d=await fetch("/api/vip",{credentials:"include"}).then(r=>r.json());
  if(!d.ok)throw new Error(d.error||"Erro");
  const s=d.settings||{};
  status.textContent=d.active?`👑 VIP ativo até ${escText(d.vip_until)}`:"Plano FREE";
  box.innerHTML=`<div class="vip-price">R$ ${(Number(s.price_cents||0)/100).toFixed(2).replace(".",",")} / ${s.duration_days} dias</div><div class="vip-benefits">${(d.benefits||[]).map(b=>`<div class="vip-benefit"><b>${escText(b.title)}</b><p>${escText(b.description)}</p></div>`).join("")}</div>`;
  if(support){
    const base=window.SUPPORT_URL||"#";
    support.href=base;
    support.textContent=d.active?"💬 Renovar VIP pelo suporte":"💬 Adquirir VIP pelo suporte";
  }
 }catch(e){box.textContent="❌ "+e.message}
}
document.addEventListener("DOMContentLoaded",loadVIP);

async function loadSecurityStatus(){
  const box=document.getElementById("securityEvents"),status=document.getElementById("securityStatus");
  if(!box)return;
  try{
    const d=await fetch("/api/security/status",{credentials:"include"}).then(r=>r.json());
    if(!d.ok)throw new Error(d.error||"Erro");
    status.textContent=d.status==="active"?"🟢 Proteção ativa":"⚠️ "+d.status;
    const events=d.events||[];
    box.innerHTML=events.length?events.map(e=>`<div class="security-event"><b>${escText(e.event_type)}</b><span>Risco ${e.risk_score}/100 • ${escText(e.action)}</span><small>${escText(e.created_at)}</small></div>`).join(""):"Nenhum evento de segurança recente.";
  }catch(e){
    box.textContent="Proteção ativa.";
  }
}

document.addEventListener("DOMContentLoaded",loadSecurityStatus);

function moneyBR(c){return "R$ "+(Number(c||0)/100).toFixed(2).replace(".",",")}
function walletTypeLabel(t){
 const m={credit:"Crédito",debit:"Débito",withdrawal_hold:"Saque pendente",withdrawal_refund:"Estorno de saque",game_reward:"Prêmio de jogo",referral_reward:"Recompensa de indicação",admin_credit:"Crédito administrativo",admin_debit:"Débito administrativo"};
 return m[t]||t;
}
async function loadWallet(){
 const summary=document.getElementById("walletSummary"),statement=document.getElementById("walletStatement");if(!summary)return;
 try{
  const [s,t]=await Promise.all([
   fetch("/api/wallet/summary",{credentials:"include"}).then(r=>r.json()),
   fetch("/api/wallet/statement?limit=50",{credentials:"include"}).then(r=>r.json())
  ]);
  if(!s.ok)throw new Error(s.error||"Erro");
  summary.innerHTML=`<div class="wallet-grid"><div><small>Saldo disponível</small><b>${moneyBR(s.balance_cents)}</b></div><div><small>Saque pendente</small><b>${moneyBR(s.pending_withdrawal_cents)}</b></div><div><small>Total de créditos</small><b>${moneyBR(s.ledger_credits_cents)}</b></div><div><small>Total de débitos</small><b>${moneyBR(s.ledger_debits_cents)}</b></div></div>`;
  statement.innerHTML=(t.transactions||[]).map(x=>{
   const positive=["credit","withdrawal_refund","game_reward","referral_reward","admin_credit"].includes(x.type);
   return `<div class="wallet-row"><span>${positive?"➕":"➖"} ${walletTypeLabel(x.type)}</span><b class="${positive?"wallet-plus":"wallet-minus"}">${positive?"+":"-"}${moneyBR(x.amount_cents)}</b><small>${escText(x.description||"")} • ${escText(x.created_at)}</small></div>`;
  }).join("")||"<p>Nenhuma movimentação registrada.</p>";
 }catch(e){summary.textContent="❌ "+e.message}
}
document.addEventListener("DOMContentLoaded",loadWallet);

async function loadAds(){
 const box=document.getElementById("adsHome");if(!box)return;
 try{
  const d=await fetch("/api/ads?placement=dashboard",{credentials:"include"}).then(r=>r.json());
  if(!d.ok)throw new Error(d.error||"Erro");
  box.innerHTML=(d.ads||[]).map(ad=>`<div class="ad-card">${ad.image_url?`<img src="${escAttr(ad.image_url)}" alt="">`:""}<div><b>${escText(ad.title)}</b><p>${escText(ad.description||"")}</p><button class="btn" onclick="openAd(${ad.id})">Conhecer</button></div></div>`).join("")||"<p>Nenhuma parceria disponível.</p>";
 }catch(e){box.textContent="Não foi possível carregar as parcerias."}
}
async function openAd(id){
 try{
  const r=await fetch("/api/ads/click",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:JSON.stringify({ad_id:id})});
  const d=await r.json();if(r.ok&&d.target_url)window.open(d.target_url,"_blank","noopener");else msg("❌ "+(d.error||"Anúncio indisponível."));
 }catch(e){msg("❌ Não foi possível abrir o anúncio.")}
}
document.addEventListener("DOMContentLoaded",loadAds);

async function checkMaintenance(){
 try{
  const d=await fetch("/api/system/status",{credentials:"include"}).then(r=>r.json());
  if(!d.ok||!d.maintenance)return;
  let overlay=document.getElementById("maintenanceOverlay");
  if(!overlay){
   overlay=document.createElement("div");overlay.id="maintenanceOverlay";overlay.className="maintenance-overlay";
   document.body.appendChild(overlay);
  }
  overlay.innerHTML=`<div class="maintenance-card"><div class="maintenance-icon">🛠️</div><h2>Manutenção</h2><p>${escText(d.message||"Sistema temporariamente indisponível.")}</p><small>Você poderá acessar novamente assim que a manutenção terminar.</small></div>`;
 }catch(e){}
}
document.addEventListener("DOMContentLoaded",checkMaintenance);

async function loadTickets(){
 const box=document.getElementById("ticketList");if(!box)return;
 try{
  const d=await fetch("/api/tickets",{credentials:"include"}).then(r=>r.json());
  if(!d.ok)throw new Error(d.error||"Erro");
  box.innerHTML=(d.tickets||[]).map(t=>`<div class="ticket-row" onclick="openTicket(${t.id})"><div><b>#${t.id} ${escText(t.subject)}</b><small>${escText(t.status)} • ${escText(t.priority)} • ${escText(t.last_message_at)}</small></div></div>`).join("")||"Nenhum ticket.";
 }catch(e){box.textContent="❌ "+e.message}
}
async function createTicket(){
 const body={subject:document.getElementById("ticketSubject").value,message:document.getElementById("ticketMessage").value,priority:document.getElementById("ticketPriority").value};
 try{const d=await fetch("/api/tickets",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:JSON.stringify(body)}).then(r=>r.json());if(!d.ok)throw new Error(d.error||"Erro");msg("✅ Ticket #"+d.ticket_id+" criado.");document.getElementById("ticketMessage").value="";loadTickets();openTicket(d.ticket_id)}catch(e){msg("❌ "+e.message)}
}
async function openTicket(id){
 const box=document.getElementById("ticketChat");
 try{
  const d=await fetch("/api/tickets/messages?ticket_id="+id,{credentials:"include"}).then(r=>r.json());
  if(!d.ok)throw new Error(d.error||"Erro");
  box.innerHTML=`<div class="ticket-chat"><h3>#${id} ${escText(d.ticket.subject)}</h3><div>${(d.messages||[]).map(m=>`<div class="ticket-msg"><b>${m.sender_type==="admin"?"🛡️ Suporte":"👤 Você"}</b><p>${escText(m.message)}</p><small>${escText(m.created_at)}</small></div>`).join("")}</div><textarea id="ticketReply" placeholder="Responder"></textarea><button class="btn" onclick="replyTicket(${id})">Enviar resposta</button></div>`;
 }catch(e){box.textContent="❌ "+e.message}
}
async function replyTicket(id){
 const message=document.getElementById("ticketReply").value;
 try{const d=await fetch("/api/tickets/message",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:JSON.stringify({ticket_id:id,message})}).then(r=>r.json());if(!d.ok)throw new Error(d.error||"Erro");openTicket(id);loadTickets()}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadTickets);
