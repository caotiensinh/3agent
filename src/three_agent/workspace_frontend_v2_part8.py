from __future__ import annotations

PART_8 = r"""document.getElementById('fileInput').addEventListener('change',e=>{state.selectedFiles=Array.from(e.target.files||[]).slice(0,8);renderAttachments();e.target.value=''});
document.getElementById('closeLibrary').onclick=()=>document.getElementById('libraryModal').classList.remove('open');
document.getElementById('libraryCancel').onclick=()=>document.getElementById('libraryModal').classList.remove('open');
document.getElementById('libraryAdd').onclick=applyLibrary;
document.getElementById('micBtn').onclick=()=>cap('voice_input').enabled?showToast('Local voice runtime is enabled but no recorder is bound to this build.'):unavailable('voice_input');
document.getElementById('sendBtn').onclick=sendMsg;
input.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMsg()}});
input.addEventListener('input',()=>{input.style.height='auto';input.style.height=Math.min(input.scrollHeight,170)+'px'});
for(const row of document.querySelectorAll('.menu-row[data-action]'))row.onclick=()=>{const action=row.dataset.action;if(action==='upload'){if(!cap('upload').enabled)return unavailable('upload');document.getElementById('fileInput').click();document.getElementById('plusMenu').classList.remove('open')}else if(action==='library')openLibrary().catch(e=>showToast(e.message));else if(action==='web_search'||action==='deep_research')setMode(action);else unavailable(action)};
document.addEventListener('click',e=>{if(!e.target.closest('#plusMenu')&&!e.target.closest('#plusBtn'))document.getElementById('plusMenu').classList.remove('open');if(!e.target.closest('.account-wrap'))document.getElementById('accountMenu').classList.remove('open')});

applySidebarState();
(async()=>{try{await api('/api/session');document.getElementById('login').classList.add('hidden');await initializeWorkspace()}catch(e){}})();
</script>
</body>
</html>"""
