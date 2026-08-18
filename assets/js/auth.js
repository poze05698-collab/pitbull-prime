const p=new URLSearchParams(location.search);
const ref=document.getElementById('ref');
if(ref&&p.get('ref')) ref.value=p.get('ref');

function showMsg(text){const el=document.getElementById('msg');if(el)el.textContent=text;}

const register=document.getElementById('register');
if(register) register.addEventListener('submit',async e=>{
  e.preventDefault();
  const btn=register.querySelector('button'); btn.disabled=true; showMsg('Criando sua conta...');
  try{
    const r=await fetch('/api/register',{method:'POST',headers:{'content-type':'application/json'},credentials:'include',
      body:JSON.stringify({
        name:document.getElementById('nome').value,
        email:register.querySelector('input[type="email"]').value,
        password:register.querySelector('input[type="password"]').value,
        referral:document.getElementById('ref')?.value||''
      })});
    const data=await r.json();
    if(!r.ok) throw new Error(data.error||'Não foi possível criar a conta.');
    showMsg('✅ Conta criada! Abrindo seu painel...');
    setTimeout(()=>location.href='dashboard.html',500);
  }catch(err){showMsg('❌ '+err.message);btn.disabled=false;}
});

const login=document.getElementById('login');
if(login) login.addEventListener('submit',async e=>{
  e.preventDefault();
  const btn=login.querySelector('button'); btn.disabled=true; showMsg('Entrando...');
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},credentials:'include',
      body:JSON.stringify({
        email:login.querySelector('input[type="email"]').value,
        password:login.querySelector('input[type="password"]').value
      })});
    const data=await r.json();
    if(!r.ok) throw new Error(data.error||'Não foi possível entrar.');
    location.href='dashboard.html';
  }catch(err){showMsg('❌ '+err.message);btn.disabled=false;}
});
