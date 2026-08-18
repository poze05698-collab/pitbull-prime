
async function getJSON(url,opts={}){const r=await fetch(url,{credentials:"include",...opts});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||"Erro");return d}
function money(c){return "R$ "+(Number(c||0)/100).toFixed(2).replace(".",",")}
function msg(t){document.getElementById("actionMsg").textContent=t}
async function loadStats(){
  try{
    const d=await getJSON("/api/admin/stats");
    sUsers.textContent=d.stats.users;sVip.textContent=d.stats.vip;sBanned.textContent=d.stats.banned;sPending.textContent=d.stats.pending_referrals;
  }catch(e){msg("❌ "+e.message)}
}
async function loadUsers(){
  const box=document.getElementById("users");box.textContent="Carregando...";
  try{
    const q=encodeURIComponent(document.getElementById("search").value.trim());
    const d=await getJSON("/api/admin/users?q="+q);
    if(!d.users.length){box.textContent="Nenhum usuário encontrado.";return}
    box.innerHTML=d.users.map(u=>`
      <div class="user-row">
        <div><b>#${u.id} ${esc(u.name)}</b><small>${esc(u.email)} • ${u.status==="banned"?"🚫 BLOQUEADO":"✅ ATIVO"} • ${u.plan}</small><small>💰 ${money(u.balance_cents)} • 👥 ${esc(u.referral_code)}</small></div>
        <div class="user-actions">
          <button class="btn" onclick="addBalance(${u.id})">💰 Saldo</button>
          <button class="btn ${u.status==="banned"?"":"danger"}" onclick="toggleBan(${u.id},'${u.status}')">${u.status==="banned"?"🔓 Desbloquear":"🚫 Bloquear"}</button>
        </div>
      </div>`).join("");
  }catch(e){box.textContent="❌ "+e.message}
}
function esc(v){return String(v??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[m]))}
async function addBalance(id){
  const value=prompt("Valor em R$ para adicionar ao saldo:");
  if(value===null)return;
  const n=Number(value.replace(",","."));
  if(!Number.isFinite(n)||n<=0){msg("❌ Valor inválido.");return}
  const reason=prompt("Motivo do crédito (opcional):")||"Crédito administrativo";
  try{
    const d=await getJSON("/api/admin/user/update",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({user_id:id,action:"add_balance",amount_cents:Math.round(n*100),reason})});
    msg("✅ "+d.message+" Novo saldo: "+money(d.new_balance_cents));loadUsers();loadStats();
  }catch(e){msg("❌ "+e.message)}
}
async function toggleBan(id,status){
  const action=status==="banned"?"unban":"ban";
  const reason=prompt(action==="ban"?"Motivo do bloqueio:":"Motivo do desbloqueio:")||"Ação administrativa";
  if(!confirm((action==="ban"?"Bloquear":"Desbloquear")+" o usuário #"+id+"?"))return;
  try{const d=await getJSON("/api/admin/user/update",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({user_id:id,action,reason})});msg("✅ "+d.message);loadUsers();loadStats()}catch(e){msg("❌ "+e.message)}
}
async function adminLogout(){await fetch("/api/logout",{method:"POST",credentials:"include"});location.href="index.html"}
document.addEventListener("DOMContentLoaded",()=>{loadStats();loadUsers()})

async function loadPrizes(){
  const box=document.getElementById("prizes"); if(!box)return;
  try{
    const d=await getJSON("/api/admin/games/prizes");
    box.innerHTML=d.prizes.map(p=>`<div class="user-row"><div><b>${p.game==="roulette"?"🎰":"🎫"} ${esc(p.label)}</b><small>Tipo: ${p.reward_type} • Valor: ${p.reward_value} • Peso: ${p.weight} • ${p.enabled?"Ativo":"Desativado"}</small></div><button class="btn" onclick="editPrize(${p.id},${p.weight},${p.reward_value},${p.enabled},${JSON.stringify(p.label)})">Editar</button></div>`).join("");
  }catch(e){box.textContent="❌ "+e.message}
}
async function editPrize(id,weight,value,enabled,label){
  const nl=prompt("Nome do prêmio:",label); if(nl===null)return;
  const nw=prompt("Peso/probabilidade relativa (maior = mais frequente):",weight); if(nw===null)return;
  const nv=prompt("Valor da recompensa (saldo em centavos, coins ou gemas):",value); if(nv===null)return;
  const en=confirm("Clique OK para deixar ativo. Cancelar = desativar.");
  try{
    const d=await getJSON("/api/admin/games/prize",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id,label:nl,weight:Number(nw),reward_value:Number(nv),enabled:en})});
    msg("✅ "+d.message);loadPrizes();
  }catch(e){msg("❌ "+e.message)}
}
const oldLoadUsers=loadUsers;
loadUsers=async()=>{await oldLoadUsers();await loadPrizes()};
document.addEventListener("DOMContentLoaded",loadPrizes);

async function loadVipCodes(){
  const box=document.getElementById("codes");if(!box)return;
  try{
    const d=await getJSON("/api/admin/vip/codes");
    box.innerHTML=d.codes.map(c=>`<div class="user-row"><div><b>🎟️ ${esc(c.code)}</b><small>${c.duration_days} dias • ${c.redemptions}/${c.max_redemptions} resgates • ${c.enabled?"Ativo":"Desativado"}</small></div><button class="btn" onclick="toggleCode(${c.id})">${c.enabled?"Desativar":"Ativar"}</button></div>`).join("")||"Nenhum código.";
  }catch(e){box.textContent="❌ "+e.message}
}
async function saveVipSettings(){
  const price=Number(document.getElementById("vipPrice").value.replace(",","."));
  const days=Number(document.getElementById("vipDays").value);
  if(!Number.isFinite(price)||!Number.isInteger(days))return msg("❌ Preencha preço e duração.");
  try{const d=await getJSON("/api/admin/vip/settings",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({price_cents:Math.round(price*100),duration_days:days})});msg("✅ "+d.message)}catch(e){msg("❌ "+e.message)}
}
async function generateCodes(){
  const days=Number(document.getElementById("codeDays").value),max=Number(document.getElementById("codeMax").value),qty=Number(document.getElementById("codeQty").value||1);
  try{const d=await getJSON("/api/admin/vip/codes",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({duration_days:days,max_redemptions:max,quantity:qty})});msg("✅ Códigos gerados: "+d.codes.join(", "));loadVipCodes()}catch(e){msg("❌ "+e.message)}
}
async function toggleCode(id){
  try{await getJSON("/api/admin/vip/code/toggle",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id})});loadVipCodes()}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadVipCodes);

function moneyA(c){return "R$ "+(Number(c||0)/100).toFixed(2).replace(".",",")}
async function loadAdminWithdrawals(){
 const box=document.getElementById("withdrawalsAdmin");if(!box)return;
 try{const d=await getJSON("/api/admin/withdrawals?status=pending");
  box.innerHTML=d.withdrawals.map(x=>`<div class="user-row"><div><b>💸 #${x.id} — ${moneyA(x.amount_cents)}</b><small>#${x.user_id} ${esc(x.user_name)} • ${esc(x.user_email)}</small><small>PIX: ${esc(x.pix_key)} (${esc(x.pix_type)})</small></div><div class="user-actions"><button class="btn" onclick="processWithdrawal(${x.id},'approve')">✅ Aprovar</button><button class="btn danger" onclick="processWithdrawal(${x.id},'reject')">❌ Rejeitar</button></div></div>`).join("")||"Nenhum saque pendente.";
 }catch(e){box.textContent="❌ "+e.message}
}
async function processWithdrawal(id,action){
 const note=prompt(action==="approve"?"Observação (opcional):":"Motivo da rejeição:");
 if(note===null)return;
 try{const d=await getJSON("/api/admin/withdrawals/process",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({withdrawal_id:id,action,note})});msg("✅ "+d.message);loadAdminWithdrawals();loadStats()}catch(e){msg("❌ "+e.message)}
}
async function saveWithdrawSettings(){
 const n=Number(document.getElementById("minWithdraw").value.replace(",","."));
 if(!Number.isFinite(n)||n<0)return msg("❌ Valor inválido.");
 try{const d=await getJSON("/api/admin/withdrawal-settings",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({min_cents:Math.round(n*100)})});msg("✅ "+d.message)}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadAdminWithdrawals);

async function loadAdminTickets(){
 const box=document.getElementById("adminTickets");if(!box)return;
 try{const d=await getJSON("/api/admin/tickets?status=open");
  box.innerHTML=(d.tickets||[]).map(t=>`<div class="user-row"><div><b>🎫 #${t.id} ${esc(t.subject)}</b><small>👤 ${esc(t.user_name)} • ${esc(t.user_email)} • ${t.priority}</small><small>${new Date(t.last_message_at.replace(' ','T')+'Z').toLocaleString('pt-BR')}</small></div><button class="btn" onclick="openAdminTicket(${t.id})">💬 Responder</button></div>`).join("")||"Nenhum ticket aberto.";
 }catch(e){box.textContent="❌ "+e.message}
}
async function openAdminTicket(id){
 const box=document.getElementById("ticketChat");
 try{
  const d=await getJSON("/api/admin/tickets/"+id);
  box.innerHTML=`<h3>🎫 #${d.ticket.id} — ${esc(d.ticket.subject)}</h3><p>👤 ${esc(d.ticket.user_name)} • ${esc(d.ticket.user_email)}</p><div class="chat-log">${d.messages.map(m=>`<div class="ref-box"><b>${m.sender_type==="admin"?"👑 Admin":"👤 Usuário"}</b><br>${esc(m.message)}<small>${new Date(m.created_at.replace(' ','T')+'Z').toLocaleString('pt-BR')}</small></div>`).join("")}</div><textarea id="ticketReply" rows="4" style="width:100%;margin-top:8px" placeholder="Digite sua resposta..."></textarea><button class="btn" onclick="replyTicket(${id})">📨 Enviar resposta</button><button class="btn" onclick="closeTicketAdmin(${id})">✅ Fechar ticket</button>`;
 }catch(e){box.textContent="❌ "+e.message}
}
async function replyTicket(id){
 const el=document.getElementById("ticketReply");const message=el.value.trim();if(!message)return msg("❌ Digite uma resposta.");
 try{const d=await getJSON("/api/admin/tickets/"+id+"/messages",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({message})});msg("✅ "+d.message);openAdminTicket(id);loadAdminTickets()}catch(e){msg("❌ "+e.message)}
}
async function closeTicketAdmin(id){
 try{const d=await getJSON("/api/admin/tickets/"+id+"/status",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({status:"closed"})});msg("✅ "+d.message);loadAdminTickets();openAdminTicket(id)}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadAdminTickets);

async function loadPlatformSettings(){
 const box=document.getElementById("platformSettings");if(!box)return;
 try{
  const d=await getJSON("/api/admin/platform/settings");
  const s=Object.fromEntries(d.settings.map(x=>[x.key,x.value]));
  box.innerHTML=`
   <label><input type="checkbox" id="maintenance_enabled" ${s.maintenance_enabled==="1"?"checked":""}> 🛠️ Modo manutenção</label>
   <label><input type="checkbox" id="registration_enabled" ${s.registration_enabled==="1"?"checked":""}> 📝 Novos cadastros</label>
   <label><input type="checkbox" id="referrals_enabled" ${s.referrals_enabled==="1"?"checked":""}> 🔗 Indicações</label>
   <label><input type="checkbox" id="games_enabled" ${s.games_enabled==="1"?"checked":""}> 🎰 Roleta/Raspadinha</label>
   <label><input type="checkbox" id="withdrawals_enabled" ${s.withdrawals_enabled==="1"?"checked":""}> 💸 Saques</label>
   <label><input type="checkbox" id="tickets_enabled" ${s.tickets_enabled==="1"?"checked":""}> 🎫 Tickets</label>
   <textarea id="maintenance_message" rows="3" style="width:100%;margin-top:10px" placeholder="Mensagem de manutenção">${esc(s.maintenance_message||"O sistema está em manutenção.")}</textarea>`;
 }catch(e){box.textContent="❌ "+e.message}
}
async function savePlatformSettings(){
 const keys=["maintenance_enabled","registration_enabled","referrals_enabled","games_enabled","withdrawals_enabled","tickets_enabled"];
 const settings={};
 for(const k of keys)settings[k]=document.getElementById(k).checked?"1":"0";
 settings.maintenance_message=document.getElementById("maintenance_message").value;
 try{const d=await getJSON("/api/admin/platform/settings",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({settings})});msg("✅ "+d.message);loadPlatformSettings()}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadPlatformSettings);

async function saveRankingSettings(){
 const metric=document.getElementById("rankMetric").value,period=document.getElementById("rankPeriod").value;
 try{const d=await getJSON("/api/admin/ranking/settings",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({enabled:true,metric,period})});msg("✅ "+d.message)}catch(e){msg("❌ "+e.message)}
}

async function loadReferralRisks(){
 const box=document.getElementById("referralRisks");if(!box)return;
 try{
  const d=await getJSON("/api/admin/referral-risks");
  box.innerHTML=(d.risks||[]).map(r=>`<div class="user-row"><div><b>${r.risk_level==="high"?"🔴":"🟠"} #${r.referral_id} ${esc(r.referrer_name)} → ${esc(r.referred_name)}</b><small>${esc(r.reason)}</small><small>${new Date(r.created_at.replace(' ','T')+'Z').toLocaleString('pt-BR')}</small></div></div>`).join("")||"Nenhum risco identificado.";
 }catch(e){box.textContent="❌ "+e.message}
}
document.addEventListener("DOMContentLoaded",loadReferralRisks);

function moneyAdmin(c){return "R$ "+(Number(c||0)/100).toFixed(2).replace(".",",")}
async function loadAdminOverview(){
 const box=document.getElementById("adminMetrics");if(!box)return;
 try{
  const d=await getJSON("/api/admin/overview"),m=d.metrics;
  box.innerHTML=`<div class="stats"><div>👥 Usuários<strong>${m.users}</strong></div><div>🟢 Ativos<strong>${m.active_users}</strong></div><div>💎 VIP<strong>${m.vip_users}</strong></div><div>💰 Saldo<strong>${moneyAdmin(m.balance_cents)}</strong></div><div>💸 Saques pendentes<strong>${m.pending_withdrawals}</strong></div><div>🎫 Tickets abertos<strong>${m.open_tickets}</strong></div><div>🔗 Indicações pendentes<strong>${m.pending_referrals}</strong></div><div>🔴 Alto risco<strong>${m.high_risk_referrals}</strong></div></div>`;
 }catch(e){box.textContent="❌ "+e.message}
}
async function searchAdminUsers(){
 const q=document.getElementById("userSearch").value.trim(),box=document.getElementById("adminUsers");if(!q)return;
 try{
  const d=await getJSON("/api/admin/users/search?q="+encodeURIComponent(q));
  box.innerHTML=(d.users||[]).map(u=>`<div class="user-row"><div><b>#${u.id} ${esc(u.name)}</b><small>${esc(u.email||"")} • ${u.plan==="VIP"?"💎 VIP":"FREE"} • ${u.status}</small><small>Saldo: ${moneyAdmin(u.balance_cents)} • XP: ${u.xp||0} • Coins: ${u.coins||0} • Gemas: ${u.gems||0}</small></div><div class="user-actions"><button class="btn" onclick="adjustUserBalance(${u.id})">💰 Saldo</button><button class="btn" onclick="toggleUserStatus(${u.id},'${u.status==="blocked"?"active":"blocked"}')">${u.status==="blocked"?"🔓 Desbloquear":"🚫 Bloquear"}</button></div></div>`).join("")||"Nenhum usuário encontrado.";
 }catch(e){box.textContent="❌ "+e.message}
}
async function toggleUserStatus(id,status){
 if(!confirm(status==="blocked"?"Bloquear este usuário?":"Desbloquear este usuário?"))return;
 try{const d=await getJSON("/api/admin/users/"+id+"/status",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({status})});msg("✅ "+d.message);searchAdminUsers();loadAdminOverview()}catch(e){msg("❌ "+e.message)}
}
async function adjustUserBalance(id){
 const v=prompt("Valor em R$ para adicionar. Para debitar, use valor negativo:");
 if(v===null)return;
 const n=Number(v.replace(",","."));
 if(!Number.isFinite(n)||n===0)return msg("❌ Valor inválido.");
 const reason=prompt("Motivo do ajuste:")||"Ajuste administrativo";
 try{const d=await getJSON("/api/admin/users/"+id+"/balance",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({amount_cents:Math.round(n*100),reason})});msg("✅ "+d.message);searchAdminUsers();loadAdminOverview()}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadAdminOverview);

async function loadPartnersAdmin(){
 const box=document.getElementById("partnerList");if(!box)return;
 try{
  const d=await getJSON("/api/admin/partners");
  box.innerHTML=(d.partners||[]).map(p=>`<div class="user-row"><div><b>#${p.id} ${esc(p.name)}</b><small>${p.status} • ${p.placement}</small><small>👁️ ${p.impressions} impressões • 🖱️ ${p.clicks} cliques</small></div><div class="user-actions"><button class="btn" onclick="togglePartner(${p.id},'${p.status==='active'?'paused':'active'}')">${p.status==='active'?'⏸️ Pausar':'▶️ Ativar'}</button></div></div>`).join("")||"Nenhum parceiro cadastrado.";
 }catch(e){box.textContent="❌ "+e.message}
}
async function createPartner(){
 const name=document.getElementById("partnerName").value.trim(),target=document.getElementById("partnerUrl").value.trim(),banner=document.getElementById("partnerBanner").value.trim();
 if(!name||!target)return msg("❌ Nome e URL são obrigatórios.");
 try{const d=await getJSON("/api/admin/partners",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name,target_url:target,banner_url:banner,placement:"dashboard",description:"Oferta de parceiro"})});msg("✅ "+d.message);loadPartnersAdmin()}catch(e){msg("❌ "+e.message)}
}
async function togglePartner(id,status){
 try{const d=await getJSON("/api/admin/partners/"+id,{method:"PATCH",headers:{"content-type":"application/json"},body:JSON.stringify({status})});msg("✅ "+d.message);loadPartnersAdmin()}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadPartnersAdmin);

async function loadPromosAdmin(){
 const box=document.getElementById("promoAdminList");if(!box)return;
 try{
  const d=await getJSON("/api/admin/promos");
  box.innerHTML=(d.promos||[]).map(p=>`<div class="user-row"><div><b>🎁 ${esc(p.code)}</b><small>${p.benefit_type} • valor ${p.benefit_value} • ${p.redemption_count}/${p.max_redemptions} resgates</small><small>${p.status} • ${p.starts_at||"sem início"} → ${p.ends_at||"sem fim"}</small></div><button class="btn" onclick="togglePromoAdmin(${p.id},'${p.status==="active"?"paused":"active"}')">${p.status==="active"?"⏸️ Pausar":"▶️ Ativar"}</button></div>`).join("")||"Nenhum código criado.";
 }catch(e){box.textContent="❌ "+e.message}
}
async function createPromoAdmin(){
 const code=document.getElementById("promoAdminCode").value.trim(),value=Number(document.getElementById("promoAdminValue").value),max=Number(document.getElementById("promoAdminMax").value),benefit_type=document.getElementById("promoAdminType").value;
 if(!code||!value||!max)return msg("❌ Preencha código, benefício e quantidade.");
 try{const d=await getJSON("/api/admin/promos",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({code,benefit_value:benefit_type==="balance_cents"?Math.round(value*100):Math.round(value),max_redemptions:max,benefit_type})});msg("✅ "+d.message);loadPromosAdmin()}catch(e){msg("❌ "+e.message)}
}
async function togglePromoAdmin(id,status){
 try{const d=await getJSON("/api/admin/promos/"+id,{method:"PATCH",headers:{"content-type":"application/json"},body:JSON.stringify({status})});msg("✅ "+d.message);loadPromosAdmin()}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadPromosAdmin);

async function loadProgressionAdmin(){
 const lbox=document.getElementById("levelList"),abox=document.getElementById("achievementList");if(!lbox||!abox)return;
 try{
  const d=await getJSON("/api/admin/levels");
  lbox.innerHTML=(d.levels||[]).map(l=>`<div class="user-row"><div><b>Nível ${l.level} — ${esc(l.title)}</b><small>${l.xp_required} XP</small></div></div>`).join("");
  abox.innerHTML=(d.achievements||[]).map(a=>`<div class="user-row"><div><b>${esc(a.icon)} ${esc(a.title)}</b><small>${esc(a.code)} • ${a.requirement_type}: ${a.requirement_value} • prêmio: ${a.reward_type} ${a.reward_value}</small></div><button class="btn" onclick="toggleAchievementAdmin(${a.id},${a.enabled?0:1})">${a.enabled?"⏸️ Desativar":"▶️ Ativar"}</button></div>`).join("")||"Nenhuma conquista.";
 }catch(e){lbox.textContent="❌ "+e.message}
}
async function saveLevelAdmin(){
 const level=Number(document.getElementById("levelNumber").value),xp_required=Number(document.getElementById("levelXP").value),title=document.getElementById("levelTitle").value.trim();
 try{const d=await getJSON("/api/admin/levels",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({level,xp_required,title})});msg("✅ "+d.message);loadProgressionAdmin()}catch(e){msg("❌ "+e.message)}
}
async function createAchievementAdmin(){
 const body={code:document.getElementById("achCode").value,title:document.getElementById("achTitle").value,description:"Conquista personalizada.",icon:"🏆",requirement_type:document.getElementById("achType").value,requirement_value:Number(document.getElementById("achReq").value),reward_type:document.getElementById("achRewardType").value,reward_value:Number(document.getElementById("achReward").value||0)};
 try{const d=await getJSON("/api/admin/achievements",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});msg("✅ "+d.message);loadProgressionAdmin()}catch(e){msg("❌ "+e.message)}
}
async function toggleAchievementAdmin(id,enabled){
 try{const d=await getJSON("/api/admin/achievements/"+id+"/toggle",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({enabled})});msg("✅ "+d.message);loadProgressionAdmin()}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadProgressionAdmin);

async function loadXPRules(){
 const box=document.getElementById("xpRulesList");if(!box)return;
 try{
  const d=await getJSON("/api/admin/xp-rules");
  box.innerHTML=(d.rules||[]).map(r=>`<div class="user-row"><div><b>⭐ ${esc(r.action)}</b><small>${r.xp} XP • limite diário: ${r.daily_limit||"sem limite"} • ${r.enabled?"ativo":"desativado"}</small><small>${esc(r.description||"")}</small></div></div>`).join("")||"Nenhuma regra cadastrada.";
 }catch(e){box.textContent="❌ "+e.message}
}
async function saveXPRule(){
 const body={
  action:document.getElementById("xpAction").value,
  xp:Number(document.getElementById("xpValue").value),
  daily_limit:Number(document.getElementById("xpLimit").value||0),
  enabled:true,
  description:document.getElementById("xpDescription").value
 };
 try{
  const d=await getJSON("/api/admin/xp-rules",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});
  msg("✅ "+d.message);loadXPRules();
 }catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadXPRules);

async function loadMissionsAdmin(){
 const box=document.getElementById("missionList");if(!box)return;
 try{
  const d=await getJSON("/api/admin/missions");
  box.innerHTML=(d.missions||[]).map(m=>`<div class="user-row"><div><b>🎯 ${esc(m.title)}</b><small>${esc(m.code)} • ${m.period} • ${m.requirement_type}: ${m.requirement_value}</small><small>🎁 ${m.reward_value} ${m.reward_type} • ${m.enabled?"ativa":"desativada"}</small></div><button class="btn" onclick="toggleMissionAdmin(${m.id},${m.enabled?0:1})">${m.enabled?"⏸️ Desativar":"▶️ Ativar"}</button></div>`).join("")||"Nenhuma missão.";
 }catch(e){box.textContent="❌ "+e.message}
}
async function createMissionAdmin(){
 const body={
  code:document.getElementById("missionCode").value,
  title:document.getElementById("missionTitle").value,
  description:document.getElementById("missionDesc").value,
  period:document.getElementById("missionPeriod").value,
  requirement_type:document.getElementById("missionReqType").value,
  requirement_value:Number(document.getElementById("missionReq").value),
  reward_type:document.getElementById("missionRewardType").value,
  reward_value:Number(document.getElementById("missionReward").value),
  enabled:true
 };
 try{const d=await getJSON("/api/admin/missions",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});msg("✅ "+d.message);loadMissionsAdmin()}catch(e){msg("❌ "+e.message)}
}
async function toggleMissionAdmin(id,enabled){
 try{const d=await getJSON("/api/admin/missions/"+id,{method:"PATCH",headers:{"content-type":"application/json"},body:JSON.stringify({enabled})});msg("✅ "+d.message);loadMissionsAdmin()}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadMissionsAdmin);

async function loadRankingRewards(){
 const box=document.getElementById("rankingRewardsList");if(!box)return;
 try{
  const d=await getJSON("/api/admin/ranking-rewards");
  box.innerHTML=(d.rewards||[]).map(r=>`<div class="user-row"><div><b>🏆 ${esc(r.period)} — ${r.position}º</b><small>🎁 ${r.reward_value} ${esc(r.reward_type)} • ${r.enabled?"ativo":"desativado"}</small></div></div>`).join("")||"Nenhum prêmio configurado.";
 }catch(e){box.textContent="❌ "+e.message}
}
async function saveRankingReward(){
 const body={period:document.getElementById("rankPeriod").value,position:Number(document.getElementById("rankPosition").value),reward_type:document.getElementById("rankRewardType").value,reward_value:Number(document.getElementById("rankRewardValue").value),enabled:true};
 try{const d=await getJSON("/api/admin/ranking-rewards",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});msg("✅ "+d.message);loadRankingRewards()}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadRankingRewards);

async function loadVIPAdmin(){
 const box=document.getElementById("vipSettingsView");if(!box)return;
 try{
  const d=await getJSON("/api/admin/vip");
  const s=d.settings||{};
  document.getElementById("vipPrice").value=s.price_cents??999;
  document.getElementById("vipDays").value=s.duration_days??30;
  document.getElementById("vipGameMult").value=s.daily_game_multiplier??2;
  document.getElementById("vipScratchMult").value=s.daily_scratch_multiplier??2;
  document.getElementById("vipBonusXP").value=s.daily_bonus_xp??15;
  document.getElementById("vipRankMult").value=s.ranking_multiplier??1.5;
  box.innerHTML=`Preço: R$ ${(Number(s.price_cents||0)/100).toFixed(2).replace(".",",")} • ${s.duration_days} dias • jogos x${s.daily_game_multiplier} • raspadinha x${s.daily_scratch_multiplier} • XP +${s.daily_bonus_xp} • ranking x${s.ranking_multiplier}`;
  document.getElementById("vipBenefitsList").innerHTML=(d.benefits||[]).map(b=>`<div class="user-row"><div><b>${esc(b.title)}</b><small>${esc(b.code)} • ${esc(b.description)}</small></div></div>`).join("")||"Nenhum benefício.";
 }catch(e){box.textContent="❌ "+e.message}
}
async function saveVIPSettings(){
 const body={price_cents:Number(document.getElementById("vipPrice").value),duration_days:Number(document.getElementById("vipDays").value),daily_game_multiplier:Number(document.getElementById("vipGameMult").value),daily_scratch_multiplier:Number(document.getElementById("vipScratchMult").value),daily_bonus_xp:Number(document.getElementById("vipBonusXP").value),ranking_multiplier:Number(document.getElementById("vipRankMult").value),enabled:true};
 try{const d=await getJSON("/api/admin/vip/settings",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});msg("✅ "+d.message);loadVIPAdmin()}catch(e){msg("❌ "+e.message)}
}
async function saveVIPBenefit(){
 const body={code:document.getElementById("vipBenefitCode").value,title:document.getElementById("vipBenefitTitle").value,description:document.getElementById("vipBenefitDesc").value,sort_order:Number(document.getElementById("vipBenefitOrder").value||0),enabled:true};
 try{const d=await getJSON("/api/admin/vip/benefits",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});msg("✅ "+d.message);loadVIPAdmin()}catch(e){msg("❌ "+e.message)}
}
async function grantVIP(){
 const body={user_id:Number(document.getElementById("vipGrantUser").value),days:Number(document.getElementById("vipGrantDays").value)};
 try{const d=await getJSON("/api/admin/vip/grant",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});msg("✅ "+d.message);loadVIPAdmin()}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadVIPAdmin);

async function loadFraudAdmin(){
 const summary=document.getElementById("fraudSummary"),events=document.getElementById("fraudEvents");if(!summary)return;
 try{
  const d=await getJSON("/api/admin/fraud"),s=d.settings||{};
  document.getElementById("fraudDaily").value=s.referral_daily_limit??20;
  document.getElementById("fraudSameIp").value=s.referral_same_ip_limit??3;
  document.getElementById("fraudReview").value=s.max_risk_review??50;
  document.getElementById("fraudBlock").value=s.max_risk_block??80;
  summary.innerHTML=`Proteção: ${s.enabled?"🟢 ativa":"🔴 desativada"} • ${s.referral_daily_limit} indicações/dia • ${s.referral_same_ip_limit} usuários/IP • revisão ${s.max_risk_review} • bloqueio ${s.max_risk_block}`;
  events.innerHTML=(d.events||[]).map(e=>`<div class="user-row"><div><b>🛡️ ${esc(e.event_type)}</b><small>${esc(e.name||"Usuário")} • risco ${e.risk_score}/100 • ${esc(e.action)}</small><small>${esc(e.created_at)}</small></div></div>`).join("")||"Nenhum evento.";
 }catch(e){summary.textContent="❌ "+e.message}
}
async function saveFraudSettings(){
 const body={enabled:true,referral_daily_limit:Number(document.getElementById("fraudDaily").value),referral_same_ip_limit:Number(document.getElementById("fraudSameIp").value),max_risk_review:Number(document.getElementById("fraudReview").value),max_risk_block:Number(document.getElementById("fraudBlock").value)};
 try{const d=await getJSON("/api/admin/fraud/settings",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});msg("✅ "+d.message);loadFraudAdmin()}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadFraudAdmin);

function moneyAdmin(c){return "R$ "+(Number(c||0)/100).toFixed(2).replace(".",",")}
async function loadWalletAdminUser(){
 const id=Number(document.getElementById("walletUserId").value);if(!id)return msg("❌ Informe o ID.");
 const box=document.getElementById("walletAdminResult");
 try{
  const d=await getJSON("/api/admin/wallet/user?user_id="+id);
  box.innerHTML=`<div><b>Saldo:</b> ${moneyAdmin(d.summary.balance_cents)} • <b>Pendente:</b> ${moneyAdmin(d.summary.pending_withdrawal_cents)}</div>`+
   (d.transactions||[]).map(x=>`<div class="user-row"><div><b>${esc(x.type)} — ${moneyAdmin(x.amount_cents)}</b><small>${esc(x.description||"")} • ${esc(x.created_at)}</small></div></div>`).join("");
 }catch(e){box.textContent="❌ "+e.message}
}
async function adjustWalletAdmin(){
 const body={user_id:Number(document.getElementById("walletUserId").value),amount_cents:Number(document.getElementById("walletAmount").value),type:document.getElementById("walletAdjustType").value,reason:document.getElementById("walletReason").value};
 try{const d=await getJSON("/api/admin/wallet/adjust",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});msg("✅ "+d.message);loadWalletAdminUser()}catch(e){msg("❌ "+e.message)}
}
async function checkWalletConsistency(){
 const box=document.getElementById("walletConsistency");
 try{
  const d=await getJSON("/api/admin/wallet/check");
  box.innerHTML=(d.inconsistencies||[]).map(x=>`<div class="user-row"><div><b>⚠️ #${x.id} ${esc(x.name)}</b><small>Saldo: ${moneyAdmin(x.balance_cents)} • Ledger: ${moneyAdmin(x.ledger_net)}</small></div></div>`).join("")||"✅ Nenhuma inconsistência encontrada.";
 }catch(e){box.textContent="❌ "+e.message}
}
document.addEventListener("DOMContentLoaded",()=>{
 const x=document.getElementById("walletUserId"); if(x)x.addEventListener("change",loadWalletAdminUser);
});

async function loadWithdrawalsAdmin(){
 const box=document.getElementById("withdrawalsAdmin");if(!box)return;
 try{
  const d=await getJSON("/api/admin/withdrawals");
  box.innerHTML=(d.withdrawals||[]).map(w=>`
   <div class="user-row">
    <div><b>#${w.id} • ${esc(w.name||"Usuário")} • R$ ${(Number(w.amount_cents||0)/100).toFixed(2).replace(".",",")}</b>
    <small>Status: ${esc(w.status)} • Pix: ${esc(w.pix_key||"não informado")}</small></div>
    ${w.status==="pending"?`<div class="search"><button class="btn" onclick="withdrawAction(${w.id},'approved')">✅ Aprovar</button><button class="btn" onclick="withdrawAction(${w.id},'rejected')">❌ Rejeitar</button></div>`:""}
   </div>`).join("")||"Nenhum saque encontrado.";
 }catch(e){box.textContent="❌ "+e.message}
}
async function withdrawAction(id,action){
 const note=prompt("Observação (opcional):")||"";
 try{
  const d=await getJSON("/api/admin/withdrawals/action",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({withdrawal_id:id,action,note})});
  msg("✅ "+d.message);loadWithdrawalsAdmin();loadWalletAdminUser();
 }catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadWithdrawalsAdmin);

async function loadPartnersAdmin(){
 const pbox=document.getElementById("partnersList"),abox=document.getElementById("adsList");if(!pbox)return;
 try{
  const d=await getJSON("/api/admin/partners");
  pbox.innerHTML=(d.partners||[]).map(p=>`<div class="user-row"><div><b>🤝 #${p.id} ${esc(p.name)}</b><small>${esc(p.status)} • ${esc(p.website_url||"sem site")}</small></div></div>`).join("")||"Nenhuma parceria.";
  abox.innerHTML=(d.ads||[]).map(a=>`<div class="user-row"><div><b>📢 #${a.id} ${esc(a.title)}</b><small>${esc(a.placement)} • ${esc(a.status)} • ${a.impressions} impressões • ${a.clicks} cliques</small></div></div>`).join("")||"Nenhum anúncio.";
 }catch(e){pbox.textContent="❌ "+e.message}
}
async function savePartner(){
 const body={id:Number(document.getElementById("partnerId").value||0),name:document.getElementById("partnerName").value,logo_url:document.getElementById("partnerLogo").value,website_url:document.getElementById("partnerSite").value,description:document.getElementById("partnerDesc").value,status:document.getElementById("partnerStatus").value,sort_order:0};
 try{const d=await getJSON("/api/admin/partners",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});msg("✅ "+d.message);loadPartnersAdmin()}catch(e){msg("❌ "+e.message)}
}
async function saveAd(){
 const body={id:Number(document.getElementById("adId").value||0),title:document.getElementById("adTitle").value,description:document.getElementById("adDesc").value,image_url:document.getElementById("adImage").value,target_url:document.getElementById("adTarget").value,partner_id:Number(document.getElementById("adPartner").value||0),placement:document.getElementById("adPlacement").value,status:document.getElementById("adStatus").value};
 try{const d=await getJSON("/api/admin/ads",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});msg("✅ "+d.message);loadPartnersAdmin()}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadPartnersAdmin);

async function loadSystemAdmin(){
 const box=document.getElementById("systemMetrics");if(!box)return;
 try{
  const d=await getJSON("/api/admin/system");
  const m=d.metrics||{};
  box.innerHTML=`<div class="system-metrics"><b>👥 ${m.users} usuários</b><b>🟢 ${m.active_users} ativos</b><b>📝 ${m.open_tickets} tickets</b><b>💸 ${m.pending_withdrawals} saques pendentes</b><b>📅 ${m.registrations_today} cadastros hoje</b></div>`;
  const s=Object.fromEntries((d.settings||[]).map(x=>[x.key,x.value]));
  document.getElementById("maintenanceEnabled").checked=s.maintenance_enabled==="1";
  document.getElementById("maintenanceAllowAdmin").checked=s.maintenance_allow_admin!=="0";
  document.getElementById("maintenanceMessage").value=s.maintenance_message||"";
 }catch(e){box.textContent="❌ "+e.message}
}
async function saveMaintenance(){
 const body={enabled:document.getElementById("maintenanceEnabled").checked,allow_admin:document.getElementById("maintenanceAllowAdmin").checked,message:document.getElementById("maintenanceMessage").value};
 try{const d=await getJSON("/api/admin/system/maintenance",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});msg("✅ "+d.message);loadSystemAdmin()}catch(e){msg("❌ "+e.message)}
}
async function runHealthCheck(){
 const box=document.getElementById("healthResult");
 try{
  const d=await getJSON("/api/admin/health");
  box.innerHTML=(d.checks||[]).map(x=>`<div class="health-row"><b>${x.status==="ok"?"🟢":x.status==="warning"?"🟡":"🔴"} ${esc(x.name)}</b><span>${esc(x.details)}</span></div>`).join("");
 }catch(e){box.textContent="❌ "+e.message}
}
async function downloadSafeExport(){
 try{
  const d=await getJSON("/api/admin/export");
  const blob=new Blob([JSON.stringify(d,null,2)],{type:"application/json"});
  const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="pitbull-prime-export.json";a.click();URL.revokeObjectURL(a.href);
  msg("✅ Exportação criada.");
 }catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadSystemAdmin);

async function loadAdminTickets(){
 const box=document.getElementById("adminTicketList");if(!box)return;
 try{
  const d=await getJSON("/api/tickets");
  box.innerHTML=(d.tickets||[]).map(t=>`<div class="user-row" onclick="openAdminTicket(${t.id})"><div><b>🎫 #${t.id} ${esc(t.subject)}</b><small>${esc(t.name||"")} • ${esc(t.status)} • ${esc(t.priority)} • ${esc(t.last_message_at)}</small></div></div>`).join("")||"Nenhum ticket.";
 }catch(e){box.textContent="❌ "+e.message}
}
async function openAdminTicket(id){
 const box=document.getElementById("adminTicketChat");
 try{
  const d=await getJSON("/api/tickets/messages?ticket_id="+id);
  box.innerHTML=`<div class="ticket-chat"><h3>#${id} ${esc(d.ticket.subject)}</h3>${(d.messages||[]).map(m=>`<div class="ticket-msg"><b>${m.sender_type==="admin"?"🛡️ Suporte":"👤 Usuário"}</b><p>${esc(m.message)}</p><small>${esc(m.created_at)}</small></div>`).join("")}<textarea id="adminTicketReply" placeholder="Responder ao usuário"></textarea><div class="search"><button class="btn" onclick="adminReplyTicket(${id})">💬 Responder</button><button class="btn" onclick="ticketAction(${id},'assign')">📌 Assumir</button><button class="btn" onclick="ticketAction(${id},'close')">✅ Fechar</button><button class="btn" onclick="ticketAction(${id},'reopen')">🔄 Reabrir</button></div></div>`;
 }catch(e){box.textContent="❌ "+e.message}
}
async function adminReplyTicket(id){
 const message=document.getElementById("adminTicketReply").value;
 try{const d=await getJSON("/api/tickets/message",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({ticket_id:id,message})});msg("✅ "+d.message);openAdminTicket(id);loadAdminTickets()}catch(e){msg("❌ "+e.message)}
}
async function ticketAction(id,action){
 try{const d=await getJSON("/api/tickets/action",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({ticket_id:id,action})});msg("✅ "+d.message);openAdminTicket(id);loadAdminTickets()}catch(e){msg("❌ "+e.message)}
}
async function saveTicketSettings(){
 const body={enabled:document.getElementById("ticketEnabled").checked,max_open_per_user:Number(document.getElementById("ticketMaxOpen").value||3),cooldown_seconds:Number(document.getElementById("ticketCooldown").value||30)};
 try{const d=await getJSON("/api/admin/ticket-settings",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});msg("✅ "+d.message)}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadAdminTickets);

async function loadSecurity(){
 const box=document.getElementById("securityEvents");if(!box)return;
 try{
  const d=await getJSON("/api/admin/security");
  const s=d.settings||{};
  document.getElementById("securityEnabled").checked=Number(s.enabled)!==0;
  document.getElementById("securityMaxRequests").value=s.max_requests_minute||60;
  document.getElementById("securityTicketLimit").value=s.max_ticket_messages_minute||10;
  document.getElementById("securityReferralLimit").value=s.max_referral_actions_hour||20;
  document.getElementById("securityStats").innerHTML=(d.stats||[]).map(x=>`<span class="security-stat">🛡️ ${esc(x.event_type)}: ${x.total}</span>`).join("");
  box.innerHTML=(d.events||[]).map(e=>`<div class="security-row"><b>${e.severity==="critical"?"🔴":e.severity==="warning"?"🟡":"🟢"} ${esc(e.event_type)}</b><span>${esc(e.name||"Sistema")} • ${esc(e.created_at)}</span><small>${esc(e.details||"")}</small></div>`).join("")||"Nenhum evento recente.";
 }catch(e){box.textContent="❌ "+e.message}
}
async function saveSecurity(){
 const body={enabled:document.getElementById("securityEnabled").checked,max_requests_minute:Number(document.getElementById("securityMaxRequests").value||60),max_ticket_messages_minute:Number(document.getElementById("securityTicketLimit").value||10),max_referral_actions_hour:Number(document.getElementById("securityReferralLimit").value||20)};
 try{const d=await getJSON("/api/admin/security",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});msg("✅ "+d.message);loadSecurity()}catch(e){msg("❌ "+e.message)}
}
document.addEventListener("DOMContentLoaded",loadSecurity);

async function loadAudit(){
 const box=document.getElementById("auditList");if(!box)return;
 try{
  const action=encodeURIComponent(document.getElementById("auditAction").value||"");
  const actor=encodeURIComponent(document.getElementById("auditActor").value||"");
  const d=await getJSON(`/api/admin/audit?limit=150&action=${action}&actor_id=${actor}`);
  box.innerHTML=(d.logs||[]).map(x=>`<div class="audit-row"><b>#${x.id} ${esc(x.action)}</b><span>Admin: ${esc(x.actor_name||x.actor_user_id||"Sistema")} • Alvo: ${esc(x.target_name||x.target_user_id||"-")} • ${esc(x.created_at)}</span><small>${esc(x.details||"")}</small></div>`).join("")||"Nenhum registro encontrado.";
 }catch(e){box.textContent="❌ "+e.message}
}
async function saveAdminNote(){
 const body={user_id:Number(document.getElementById("noteUserId").value||0),note:document.getElementById("adminNote").value};
 try{const d=await getJSON("/api/admin/notes",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});msg("✅ "+d.message);document.getElementById("adminNote").value="";loadAdminNotes();loadAudit()}catch(e){msg("❌ "+e.message)}
}
async function loadAdminNotes(){
 const id=Number(document.getElementById("noteUserId").value||0);
 const box=document.getElementById("notesList");if(!box)return;
 try{
  const d=await getJSON("/api/admin/notes"+(id?`?user_id=${id}`:""));
  box.innerHTML=(d.notes||[]).map(n=>`<div class="audit-row"><b>📝 ${esc(n.admin_name||n.admin_id)}</b><span>${esc(n.created_at)}${n.target_user_id?` • usuário #${n.target_user_id}`:""}</span><small>${esc(n.note)}</small></div>`).join("")||"Nenhuma anotação.";
 }catch(e){box.textContent="❌ "+e.message}
}
document.addEventListener("DOMContentLoaded",()=>{loadAudit();loadAdminNotes()});

function showDeployChecklist(){
 const b=document.getElementById("deployChecklist");if(!b)return;
 const items=["Backup do banco realizado","Schema revisado","Cadastro/login testados","Indicações testadas","Carteira e extrato testados","Roleta/raspadinha testadas","VIP testado","Saque testado","Tickets e resposta testados","Manutenção testada","Parcerias/publicidade testadas","Auditoria testada"];
 b.innerHTML="<ol>"+items.map(x=>`<li>☐ ${esc(x)}</li>`).join("")+"</ol><p><b>Importante:</b> esta lista é preventiva; não altera dados.</p>";
}
