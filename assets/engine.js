/* ============================================================
   puppylovers.club — 공용 엔진
   글 목록·뷰어·검색 + 사이트 내장 글쓰기(깃허브 API) + 비밀글 암호화
   각 페이지는 window.PL_CONFIG / window.PL_TEMPLATES 를 정의해서 사용
   ============================================================ */
(function(){
'use strict';
const C = window.PL_CONFIG;          // {owner, repo, branch, base}
const T = window.PL_TEMPLATES;       // {list(post), pinned(post), gallery(item)}
const $ = s => document.querySelector(s);
const enc = new TextEncoder(), dec = new TextDecoder();

const state = { data:null, view:'recent', q:'', current:null, editId:null };

/* ---------- 유틸 ---------- */
const b64 = buf => {
  const bytes = new Uint8Array(buf.buffer || buf); let bin = '';
  const CH = 0x8000;
  for(let i=0; i<bytes.length; i+=CH)
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i+CH));
  return btoa(bin);
};
const unb64 = s => Uint8Array.from(atob(s), c=>c.charCodeAt(0));
const b64utf8 = str => { // 유니코드 안전 base64 (깃허브 업로드용)
  const bytes = enc.encode(str); let bin='';
  bytes.forEach(b=>bin+=String.fromCharCode(b));
  return btoa(bin);
};
const esc = s => String(s).replace(/[&<>"']/g, m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const today = () => { const d=new Date();
  return d.getFullYear()+'.'+String(d.getMonth()+1).padStart(2,'0')+'.'+String(d.getDate()).padStart(2,'0'); };
const token = { get:()=>localStorage.getItem('pl_token')||'',
                set:v=>localStorage.setItem('pl_token',v) };

/* ---------- 암호화 (PBKDF2 + AES-GCM) ---------- */
async function derive(pw, salt){
  const km = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations:150000, hash:'SHA-256'},
    km, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}
async function encrypt(pw, text){
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await derive(pw, salt);
  const ct   = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, enc.encode(text));
  return JSON.stringify({s:b64(salt), i:b64(iv), d:b64(ct)});
}
async function decrypt(pw, blob){
  const o = JSON.parse(blob);
  const key = await derive(pw, unb64(o.s));
  const pt  = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(o.i)}, key, unb64(o.d));
  return dec.decode(pt);
}

/* ---------- 깃허브 API ---------- */
async function gh(path, opt={}){
  const r = await fetch('https://api.github.com/repos/'+C.owner+'/'+C.repo+'/contents/'+path
      +(opt.method==='GET'||!opt.method ? '?ref='+C.branch : ''),
    Object.assign({headers:{
      'Authorization':'Bearer '+token.get(),
      'Accept':'application/vnd.github+json'
    }}, opt));
  if(!r.ok && r.status!==404) throw new Error('GitHub API '+r.status);
  return r.status===404 ? null : r.json();
}
async function api(path, method, bodyObj){
  const r = await fetch('https://api.github.com/repos/'+C.owner+'/'+C.repo+path, {
    method: method||'GET',
    headers:{'Authorization':'Bearer '+token.get(),'Accept':'application/vnd.github+json'},
    body: bodyObj ? JSON.stringify(bodyObj) : undefined
  });
  if(!r.ok) throw new Error('API '+r.status);
  return r.json();
}
/* 대용량 파일: blob → tree → commit → ref (화물 전용 통로) */
async function gitDeletePath(path, message){
  for(let i=0;i<3;i++){
    try{
      const ref    = await api('/git/ref/heads/'+C.branch);
      const head   = ref.object.sha;
      const commit = await api('/git/commits/'+head);
      const tree   = await api('/git/trees','POST',{
        base_tree: commit.tree.sha,
        tree:[{path, mode:'100644', type:'blob', sha:null}]
      });
      const newC   = await api('/git/commits','POST',{message, tree:tree.sha, parents:[head]});
      await api('/git/refs/heads/'+C.branch,'PATCH',{sha:newC.sha});
      return {ok:true};
    }catch(e){
      if(i===2) throw new Error('파일 삭제 실패 — 잠시 후 다시 시도해 주세요');
      await new Promise(res=>setTimeout(res, 900*(i+1)));
    }
  }
}
async function putLarge(path, contentB64, message){
  const blob = await api('/git/blobs','POST',{content:contentB64, encoding:'base64'});
  for(let i=0;i<3;i++){
    try{
      const ref    = await api('/git/ref/heads/'+C.branch);
      const head   = ref.object.sha;
      const commit = await api('/git/commits/'+head);
      const tree   = await api('/git/trees','POST',{
        base_tree: commit.tree.sha,
        tree:[{path, mode:'100644', type:'blob', sha: blob.sha}]
      });
      const newC   = await api('/git/commits','POST',{message, tree:tree.sha, parents:[head]});
      await api('/git/refs/heads/'+C.branch,'PATCH',{sha:newC.sha});
      return {ok:true};
    }catch(e){
      if(i===2) throw new Error('대용량 업로드 실패 — 잠시 후 다시 시도해 주세요');
      await new Promise(res=>setTimeout(res, 900*(i+1)));
    }
  }
}
async function putFile(path, contentB64, msg){
  if(contentB64.length > 900000) return putLarge(path, contentB64, msg); // ~0.7MB 이상은 화물 통로
  let lastStatus = 0;
  for(let i=0; i<3; i++){
    const cur = await gh(path, {method:'GET'}).catch(()=>null);
    const body = {message:msg, content:contentB64, branch:C.branch};
    if(cur && cur.sha) body.sha = cur.sha;
    const r = await fetch('https://api.github.com/repos/'+C.owner+'/'+C.repo+'/contents/'+path, {
      method:'PUT',
      headers:{'Authorization':'Bearer '+token.get(),'Accept':'application/vnd.github+json'},
      body: JSON.stringify(body)
    });
    if(r.ok) return r.json();
    lastStatus = r.status;
    if(r.status!==409) throw new Error('업로드 실패 ('+r.status+')');
    await new Promise(res=>setTimeout(res, 900*(i+1)));
  }
  return putLarge(path, contentB64, msg);  // 일반 통로가 계속 막히면 화물 통로로 폴백
}
const P = p => C.base + '/' + p; // 저장소 내 경로

/* ---------- 데이터 ---------- */
async function loadData(){
  const r = await fetch('data.json?t='+Date.now());
  state.data = await r.json();
  (state.data.posts||[]).forEach(p=>{ if(p.raw || p.src) p.excerpt=''; });
}
/* 발행/삭제 직전엔 반드시 저장소 원본에서 최신 목차를 읽는다
   (사이트 반영 지연 중의 옛 목차 위에 덮어써서 글이 증발하는 사고 방지) */
async function loadDataAPI(){
  const cur = await gh(P('data.json'), {method:'GET'});
  if(!cur || !cur.content) throw new Error('index');
  state.data = JSON.parse(dec.decode(unb64(cur.content.replace(/\s/g,''))));
  state.data.posts = state.data.posts||[];
  state.data.gallery = state.data.gallery||[];
  state.data.posts.forEach(p=>{ if(p.raw || p.src) p.excerpt=''; });
}
async function saveData(msg){
  await putFile(P('data.json'), b64utf8(JSON.stringify(state.data, null, 2)), msg);
}

/* ---------- 렌더링 ---------- */
function posts(){ return state.data.posts.slice().sort((a,b)=> b.id.localeCompare(a.id)); }
function render(){
  const listEl = $('#pl-list'), pinEl = $('#pl-pinned');
  if(!listEl) return;
  let items = posts();
  if(state.view!=='recent' && state.view!=='all' && state.view!=='gallery')
    items = items.filter(p=>p.cat===state.view);
  if(state.q) items = items.filter(p=>p.title.toLowerCase().includes(state.q));
  const pinned = items.find(p=>p.pinned);
  const rest = items.filter(p=>!p.pinned);
  if(pinEl) pinEl.innerHTML = (state.view==='recent' && !state.q && pinned) ? T.pinned(pinned) : '';
  const shown = state.view==='recent' && !state.q ? rest.slice(0,5) : rest;
  listEl.innerHTML = state.view==='gallery' ? ''
    : shown.length
      ? shown.map(T.list).join('')
      : '<p class="pl-empty">아직 글이 없습니다.</p>';
  // 갤러리 (gallery 뷰에서는 전체 표시)
  const g = $('#pl-gallery');
  if(g){
    const gi = (state.data.gallery||[]).slice().reverse();
    const arr = state.view==='gallery' ? gi : gi.slice(0,6);
    g.innerHTML = arr.length ? arr.map(T.gallery).join('')
                             : '<p class="pl-empty">아직 이미지가 없습니다.</p>';
    g.querySelectorAll('[data-file]').forEach(el=>{
      el.addEventListener('click', ev=>{
        ev.preventDefault();
        openImage(el.dataset.file, el.dataset.title||'');
      });
      const im = el.querySelector('img'); if(im) im.setAttribute('draggable','false');
    });
  }
  // 카운트/상태
  document.querySelectorAll('[data-count]').forEach(el=>{
    const c = el.dataset.count;
    el.textContent = c==='all' ? state.data.posts.length
      : c==='gallery' ? (state.data.gallery||[]).length
      : state.data.posts.filter(p=>p.cat===c).length;
  });
  const last = $('#pl-last'); if(last && posts()[0]) last.textContent = posts()[0].date;
  const secHead = $('#pl-view-label');
  if(secHead) secHead.textContent = state.view==='recent' ? 'RECENT'
    : state.view==='all' ? 'ALL POSTS'
    : state.view==='gallery' ? 'GALLERY' : state.view.toUpperCase();
  document.querySelectorAll('[data-cat]').forEach(a=>{
    a.classList.toggle('on', a.dataset.cat===state.view);
  });
}

/* ---------- 뷰어 ---------- */
/* ---------- 글 열기: 전용 페이지로 이동 ---------- */
function openPost(id){ location.href = 'post.html?p='+encodeURIComponent(id); }
function closeViewer(){ const v=$('#pl-viewer'); if(v) v.classList.remove('show'); }

async function loadPostBody(p){
  const r = await fetch(p.file+'?t='+Date.now());
  if(!r.ok) throw new Error('nf');
  const raw = await r.text();
  if(p.secret){
    const pw = prompt('비밀번호를 입력하세요');
    if(pw===null) return null;
    try{ return await decrypt(pw, raw); }
    catch(e){ alert('비밀번호가 맞지 않습니다.'); return null; }
  }
  return raw;
}

/* ---------- 관리(글쓰기) 패널 ---------- */
function adminHTML(){ return `
<div id="pl-viewer"><div class="pl-v-card">
  <button class="pl-x" onclick="PL.closeViewer()">✕</button>
  <p class="pl-v-meta"></p><h2 class="pl-v-title"></h2>
  <div class="pl-v-body"></div>
  <div class="pl-v-actions">
    <button onclick="PL.copyLink()">🔗 링크 복사</button>
    <button id="pl-del" onclick="PL.deletePost()">🗑 삭제</button>
  </div>
</div></div>

<div id="pl-lb" onclick="PL.closeImage(event)">
  <figure>
    <img id="pl-lb-img" draggable="false" alt="">
    <span class="pl-lb-shield"></span>
  </figure>
  <p id="pl-lb-t"></p>
  <button class="pl-x" onclick="PL.closeImage()">✕</button>
</div>

<button id="pl-pen" title="글쓰기" onclick="PL.togglePanel()">✎</button>

<div id="pl-panel"><div class="pl-p-card">
  <button class="pl-x" onclick="PL.togglePanel()">✕</button>
  <div class="pl-tabs">
    <button data-tab="post" class="on">새 글</button>
    <button data-tab="log">로그 업로드</button>
    <button data-tab="img">갤러리</button>
    <button data-tab="set">설정</button>
  </div>

  <div class="pl-tab" data-pane="post">
    <input id="pl-title" placeholder="제목">
    <div class="pl-row">
      <select id="pl-cat"><option>archive</option><option>ooc</option></select>
      <label class="pl-chk"><input type="checkbox" id="pl-secret"> 비밀글</label>
      <input id="pl-pw" placeholder="비밀번호" style="display:none">
      <label class="pl-chk"><input type="checkbox" id="pl-pin"> 고정</label>
    </div>
    <textarea id="pl-body" placeholder="본문 (줄바꿈 그대로 반영됩니다)"></textarea>
    <button class="pl-go" onclick="PL.publish()">발행</button>
  </div>

  <div class="pl-tab" data-pane="log" style="display:none">
    <input id="pl-log-title" placeholder="로그 제목">
    <div class="pl-row">
      <select id="pl-log-cat"><option>ooc</option><option>archive</option></select>
      <label class="pl-chk"><input type="checkbox" id="pl-log-secret"> 비밀글</label>
      <input id="pl-log-pw" placeholder="비밀번호" style="display:none">
    </div>
    <input type="file" id="pl-log-file" accept=".html,.htm,.txt">
    <button class="pl-go" onclick="PL.publishLog()">업로드</button>
  </div>

  <div class="pl-tab" data-pane="img" style="display:none">
    <input id="pl-img-title" placeholder="이미지 제목">
    <input type="file" id="pl-img-file" accept="image/*">
    <button class="pl-go" onclick="PL.publishImage()">업로드</button>
  </div>

  <div class="pl-tab" data-pane="set" style="display:none">
    <p class="pl-help">깃허브 토큰(Contents 쓰기 권한)을 한 번만 등록하면
    이 브라우저에서 계속 발행할 수 있어요.</p>
    <input id="pl-token" type="password" placeholder="ghp_ 로 시작하는 토큰">
    <button class="pl-go" onclick="PL.saveToken()">저장</button>
  </div>

  <p id="pl-msg"></p>
</div></div>`;}

function adminCSS(){ return `
#pl-pen{position:fixed;right:22px;bottom:22px;width:44px;height:44px;border-radius:50%;
  border:1px solid var(--pl-line,#8888);background:var(--pl-panel-bg,#fff);
  color:var(--pl-accent,#555);font-size:17px;cursor:pointer;z-index:60;
  box-shadow:0 6px 18px -8px rgba(0,0,0,.4)}
#pl-panel,#pl-viewer{position:fixed;inset:0;background:rgba(10,14,20,.55);
  display:none;align-items:center;justify-content:center;z-index:70;padding:18px}
#pl-panel.show,#pl-viewer.show{display:flex}
.pl-p-card,.pl-v-card{position:relative;width:min(560px,100%);max-height:88vh;overflow:auto;
  background:var(--pl-panel-bg,#fff);color:var(--pl-panel-text,#333);
  border:1px solid var(--pl-line,#ddd);border-radius:16px;padding:26px 24px}
.pl-x{position:absolute;top:14px;right:16px;border:none;background:none;cursor:pointer;
  color:inherit;font-size:14px;opacity:.6}
.pl-x:hover{opacity:1}
.pl-tabs{display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap}
.pl-tabs button{border:1px solid var(--pl-line,#ddd);background:none;color:inherit;
  border-radius:999px;padding:6px 14px;font-size:12px;cursor:pointer;font-family:inherit}
.pl-tabs button.on{background:var(--pl-accent,#555);color:var(--pl-accent-text,#fff);border-color:transparent}
.pl-tab input[type=text],.pl-tab input:not([type=file]):not([type=checkbox]),.pl-tab select,.pl-tab textarea{
  width:100%;margin-bottom:10px;padding:10px 12px;font-size:13px;font-family:inherit;
  border:1px solid var(--pl-line,#ddd);border-radius:9px;background:transparent;color:inherit}
.pl-tab textarea{min-height:180px;resize:vertical;line-height:1.8}
.pl-row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
.pl-row select{width:auto;margin-bottom:0}
.pl-row input{margin-bottom:0;width:auto;flex:1}
.pl-chk{font-size:12px;display:inline-flex;gap:5px;align-items:center;white-space:nowrap}
.pl-go{border:none;border-radius:9px;padding:11px 0;width:100%;cursor:pointer;
  background:var(--pl-accent,#555);color:var(--pl-accent-text,#fff);font-size:13px;font-family:inherit}
.pl-help{font-size:12px;opacity:.75;margin-bottom:10px;line-height:1.7}
#pl-msg{margin-top:10px;font-size:12px;opacity:.85}
.pl-empty{font-size:12.5px;opacity:.6;padding:8px 4px}
#pl-lb{position:fixed;inset:0;display:none;align-items:center;justify-content:center;
  flex-direction:column;gap:12px;background:rgba(8,10,14,.88);z-index:80;padding:26px}
#pl-lb.show{display:flex}
#pl-lb figure{position:relative;max-width:min(1000px,94vw);max-height:82vh;margin:0}
#pl-lb img{max-width:100%;max-height:82vh;border-radius:10px;display:block;
  user-select:none;-webkit-user-drag:none;pointer-events:none}
.pl-lb-shield{position:absolute;inset:0}
#pl-lb-t{font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:.15em;
  color:rgba(255,255,255,.75)}
#pl-lb .pl-x{position:fixed;top:18px;right:22px;color:#fff;font-size:18px;opacity:.85}
.pl-v-meta{font-size:11px;opacity:.6;letter-spacing:.08em}
.pl-v-title{margin:4px 0 14px;font-size:19px}
.pl-v-body{font-size:14px;line-height:2;white-space:normal}
.pl-v-body p{margin-bottom:1em}
.pl-v-actions{margin-top:20px;display:flex;gap:8px;border-top:1px solid var(--pl-line,#ddd);padding-top:14px}
.pl-v-actions button{border:1px solid var(--pl-line,#ddd);background:none;color:inherit;
  border-radius:8px;padding:7px 14px;font-size:12px;cursor:pointer;font-family:inherit;opacity:.85}
.pl-v-actions button:hover{opacity:1;border-color:var(--pl-accent,#555)}`;}

function msg(t){ $('#pl-msg').textContent = t; }

/* ---------- 발행 ---------- */
function newId(){ return Date.now().toString(36); }
function bodyToHTML(text){
  return text.split(/\n{2,}/).map(p=>'<p>'+esc(p).replace(/\n/g,'<br>')+'</p>').join('\n');
}
async function publishCore({title, cat, secret, pw, pinned, bodyHTML, srcName, raw}){
  if(!token.get()){ msg('먼저 [설정] 탭에서 토큰을 등록하세요.'); return; }
  if(!title){ msg('제목을 입력하세요.'); return; }
  if(secret && !pw){ msg('비밀글 비밀번호를 입력하세요.'); return; }
  msg(state.editId ? '수정 저장 중...' : '발행 중...');
  try{ await loadDataAPI(); }
  catch(e){ msg('목차(data.json)를 불러오지 못해 중단했어요 — 글이 사라지는 걸 막기 위해서예요. 잠시 후 다시 시도해 주세요.'); return; }
  const editing = state.editId;
  const old = editing ? state.data.posts.find(x=>x.id===editing) : null;
  const id = editing || newId();
  const fname = 'posts/'+id + (secret?'.enc':'.html');
  const content = secret ? await encrypt(pw, bodyHTML) : bodyHTML;
  await putFile(P(fname), b64utf8(content), (editing?'edit: ':'post: ')+title);
  if(old && old.file !== fname){
    try{ await gitDeletePath(P(old.file), 'cleanup: '+title); }catch(e){}
  }
  if(pinned) state.data.posts.forEach(p=>p.pinned=false);
  const isRaw = raw!==undefined ? !!raw : !!(old && old.raw);
  const entry = {
    id, title, cat, date: old ? old.date : today(), secret:!!secret, pinned:!!pinned,
    raw: isRaw,
    excerpt: (secret || isRaw) ? '' :
      bodyHTML.replace(/<style[\s\S]*?<\/style>/gi,'').replace(/<script[\s\S]*?<\/script>/gi,'')
              .replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim().slice(0,80),
    file:fname, src: srcName || (old && old.src) || ''
  };
  if(old) state.data.posts = state.data.posts.map(x=>x.id===id ? entry : x);
  else state.data.posts.push(entry);
  await saveData('index: '+title);
  state.editId = null;
  const btn = document.querySelector('[data-pane="post"] .pl-go');
  if(btn) btn.textContent = '발행';
  msg(editing ? '수정 완료! 사이트 반영까지 30초~1분.' : '발행 완료! 사이트 반영까지 30초~1분 걸려요.');
  render();
}
async function publish(){
  const secret = $('#pl-secret').checked;
  await publishCore({
    title:$('#pl-title').value.trim(), cat:$('#pl-cat').value,
    secret, pw:$('#pl-pw').value, pinned:$('#pl-pin').checked,
    bodyHTML: bodyToHTML($('#pl-body').value)
  }).catch(e=>msg('오류: '+e.message));
}
async function publishLog(){
  const f = $('#pl-log-file').files[0];
  if(!f){ msg('로그 파일을 선택하세요.'); return; }
  if(f.size > 20*1024*1024){ msg('파일이 20MB를 넘어요 — 이미지가 많은 로그라면 이미지를 갤러리로 나눠 올려주세요.'); return; }
  const text = await f.text();
  const secret = $('#pl-log-secret').checked;
  await publishCore({
    title: $('#pl-log-title').value.trim() || f.name.replace(/\.[^.]+$/,''),
    cat: $('#pl-log-cat').value, secret, pw:$('#pl-log-pw').value, pinned:false,
    bodyHTML:text, srcName:f.name, raw:true
  }).catch(e=>msg('오류: '+e.message));
}
async function publishImage(){
  if(!token.get()){ msg('먼저 [설정] 탭에서 토큰을 등록하세요.'); return; }
  const f = $('#pl-img-file').files[0];
  if(!f){ msg('이미지를 선택하세요.'); return; }
  msg('업로드 중...');
  try{ await loadDataAPI(); }
  catch(e){ msg('목차(data.json)를 불러오지 못해 중단했어요. 잠시 후 다시 시도해 주세요.'); return; }
  const buf = await f.arrayBuffer();
  const name = 'gallery/'+Date.now().toString(36)+'-'+f.name.replace(/[^a-zA-Z0-9._-]/g,'');
  await putFile(P(name), b64(buf), 'gallery: '+f.name).catch(e=>{msg('오류: '+e.message);throw e;});
  (state.data.gallery=state.data.gallery||[]).push({file:name, title:$('#pl-img-title').value.trim()||f.name});
  await saveData('gallery index');
  msg('업로드 완료! 반영까지 30초~1분.');
  render();
}
function saveToken(){ token.set($('#pl-token').value.trim()); msg('토큰 저장 완료. 이제 발행할 수 있어요.'); }

/* ---------- 글 페이지(post.html) ---------- */
let curPost = null, curBody = null;
function htmlToText(html){
  const d = document.createElement('div');
  d.innerHTML = String(html).replace(/<br\s*\/?>/gi,'\n').replace(/<\/p>/gi,'\n\n');
  return d.textContent.replace(/\n{3,}/g,'\n\n').trim();
}
function editPost(){
  const p = curPost; if(!p) return;
  if(!token.get()){ alert('수정하려면 ✎ → 설정에서 토큰을 먼저 등록하세요.'); return; }
  if(curBody===null){ alert('비밀글은 비밀번호로 연 뒤에 수정할 수 있어요.\n새로고침해서 비밀번호를 입력해 주세요.'); return; }
  state.editId = p.id;
  $('#pl-title').value = p.title;
  $('#pl-cat').value = p.cat;
  $('#pl-pin').checked = !!p.pinned;
  $('#pl-secret').checked = !!p.secret;
  $('#pl-pw').style.display = p.secret ? '' : 'none';
  $('#pl-pw').value = '';
  $('#pl-body').value = htmlToText(curBody);
  const btn = document.querySelector('[data-pane="post"] .pl-go');
  if(btn) btn.textContent = '수정 저장';
  document.querySelector('.pl-tabs button[data-tab="post"]').click();
  $('#pl-panel').classList.add('show');
  if(p.secret) msg('비밀글 수정: 저장할 때 비밀번호를 다시 입력해 주세요.');
}
function copyLink(){
  const url = location.href;
  const done = ()=>alert('링크를 복사했어요!\n'+url);
  if(navigator.clipboard) navigator.clipboard.writeText(url).then(done)
    .catch(()=>prompt('이 링크를 복사하세요', url));
  else prompt('이 링크를 복사하세요', url);
}
async function deletePost(){
  const p = curPost; if(!p) return;
  if(!token.get()){ alert('삭제하려면 ✎ → 설정에서 토큰을 먼저 등록하세요.'); return; }
  if(!confirm('「'+p.title+'」 글을 삭제할까요? 되돌릴 수 없어요.')) return;
  try{
    try{ await loadDataAPI(); }
    catch(e){ alert('목차(data.json)를 불러오지 못해 중단했어요. 잠시 후 다시 시도해 주세요.'); return; }
    try{ await gitDeletePath(P(p.file), 'delete: '+p.title); }
    catch(e){ /* 파일이 이미 없거나 삭제 실패해도 목록 정리는 계속 */ }
    state.data.posts = state.data.posts.filter(x=>x.id!==p.id);
    await saveData('index: delete '+p.title);
    alert('삭제했어요. 목록으로 돌아갈게요. (사이트 반영까지 30초~1분)');
    location.href = './';
  }catch(e){ alert('오류: '+e.message); }
}
function mountFrame(container, {src, srcdoc}){
  if(!container) return;
  const fr = document.createElement('iframe');
  fr.style.cssText = 'width:100%;border:0;min-height:70vh;display:block;border-radius:10px;background:transparent';
  const fit = ()=>{ try{
    const d = fr.contentWindow.document;
    fr.style.height = Math.max(d.documentElement.scrollHeight, d.body ? d.body.scrollHeight : 0) + 24 + 'px';
  }catch(e){} };
  fr.addEventListener('load', ()=>{ fit(); setTimeout(fit, 400); setTimeout(fit, 1500); });
  if(src) fr.src = src; else fr.srcdoc = srcdoc;
  container.appendChild(fr);
}

async function initPostPage(){
  const m = location.search.match(/[?&]p=([^&]+)/);
  const id = m ? decodeURIComponent(m[1]) : null;
  const t=$('#pp-title'), meta=$('#pp-meta'), body=$('#pp-body');
  await loadData().catch(()=>{ state.data={posts:[],gallery:[]}; });
  const p = id ? state.data.posts.find(x=>x.id===id) : null;
  if(!p){
    if(t) t.textContent='글을 찾을 수 없어요';
    if(body) body.innerHTML='<p>삭제되었거나 주소가 잘못되었어요.</p>';
    return;
  }
  curPost = p;
  if(t) t.textContent = p.title;
  document.title = p.title;
  if(meta) meta.textContent = p.cat+' · '+p.date+(p.secret?' · SECRET':'');
  const del=$('#pp-del'); if(del && !token.get()) del.style.display='none';
  const ed=$('#pp-edit'); if(ed && (!token.get() || p.raw || p.src)) ed.style.display='none';
  const isRaw = !!(p.raw || p.src);   // 업로드된 로그 = 자체 디자인을 가진 완성 문서
  try{
    if(isRaw && !p.secret){
      curBody = null;
      const chk = await fetch(p.file+'?t='+Date.now());
      if(!chk.ok){
        if(body) body.innerHTML = '<p>로그 파일을 찾을 수 없어요. 방금 올렸다면 1~2분 뒤 새로고침, 이미 지운 파일이라면 아래 🗑 삭제로 목록에서 정리해 주세요.</p>';
        return;
      }
      if(body) body.innerHTML = '';
      mountFrame(body, {src: p.file+'?t='+Date.now()});
      return;
    }
    const html = await loadPostBody(p);
    curBody = html;
    if(html===null){
      if(body) body.innerHTML = '<p>비밀글입니다. 새로고침하면 비밀번호를 다시 입력할 수 있어요.</p>';
      return;
    }
    if(isRaw){
      if(body) body.innerHTML = '';
      mountFrame(body, {srcdoc: html});
    } else if(body) body.innerHTML = html;
  }catch(e){
    if(body) body.innerHTML = '<p>글을 불러오지 못했어요. 방금 발행한 글이라면 1~2분 뒤 새로고침해 주세요.</p>';
  }
}

/* ---------- 초기화 ---------- */
function bind(){
  document.body.insertAdjacentHTML('beforeend', adminHTML());
  const st = document.createElement('style'); st.textContent = adminCSS();
  document.head.appendChild(st);
  // ✎ 버튼은 관리자(토큰 보유)에게만 — 새 기기에서는 주소 뒤에 ?admin 붙여 접속하면 표시
  if(!token.get() && !/[?#&]admin/.test(location.search + location.hash)){
    const pen = $('#pl-pen'); if(pen) pen.style.display = 'none';
  }
  document.addEventListener('contextmenu', e=>{
    if(e.target.closest && (e.target.closest('#pl-lb') || e.target.closest('#pl-gallery'))) e.preventDefault();
  });
  $('#pl-secret').addEventListener('change', e=>$('#pl-pw').style.display = e.target.checked?'':'none');
  $('#pl-log-secret').addEventListener('change', e=>$('#pl-log-pw').style.display = e.target.checked?'':'none');
  document.querySelectorAll('.pl-tabs button').forEach(b=>b.addEventListener('click',()=>{
    document.querySelectorAll('.pl-tabs button').forEach(x=>x.classList.toggle('on',x===b));
    document.querySelectorAll('.pl-tab').forEach(p=>p.style.display = p.dataset.pane===b.dataset.tab?'':'none');
  }));
  document.querySelectorAll('[data-cat]').forEach(a=>a.addEventListener('click',e=>{
    e.preventDefault();
    state.view = (state.view===a.dataset.cat) ? 'recent' : a.dataset.cat;
    render();
  }));
  const s = $('#pl-search');
  if(s) s.addEventListener('input', ()=>{ state.q = s.value.trim().toLowerCase(); render(); });
  $('#pl-viewer').addEventListener('click', e=>{ if(e.target.id==='pl-viewer') closeViewer(); });
}
function togglePanel(){ $('#pl-panel').classList.toggle('show'); }

/* ---------- 갤러리 라이트박스 ---------- */
function openImage(file, title){
  const lb = $('#pl-lb'); if(!lb) return;
  $('#pl-lb-img').src = file;
  $('#pl-lb-t').textContent = title || '';
  lb.classList.add('show');
}
function closeImage(e){
  if(e && e.target && (e.target.id==='pl-lb-img' || e.target.classList.contains('pl-lb-shield'))) return;
  const lb = $('#pl-lb'); if(lb) lb.classList.remove('show');
}

window.PL = { openPost, closeViewer, togglePanel, publish, publishLog, publishImage, saveToken, copyLink, deletePost, editPost, openImage, closeImage };
document.addEventListener('DOMContentLoaded', async ()=>{
  bind();
  if(window.PL_PAGE==='post'){ initPostPage(); return; }
  await loadData().catch(()=>{ state.data={posts:[],gallery:[]}; });
  render();
  const m = location.hash.match(/^#p=(.+)$/);
  if(m) location.replace('post.html?p='+encodeURIComponent(m[1]));
});
})();
