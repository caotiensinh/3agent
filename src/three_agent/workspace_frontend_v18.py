from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v17 import WORKSPACE_HTML_V17


html = WORKSPACE_HTML_V17

# Add business-document support at the newest UI layer. Older frontend modules
# remain rollback contracts and are not rewritten.
html = _replace_once(
    html,
    'accept=".txt,.md,.markdown,.html,.htm,.zip,.png,.jpg,.jpeg,.webp,text/plain,text/markdown,text/html,application/zip,image/png,image/jpeg,image/webp"',
    'accept=".txt,.md,.markdown,.html,.htm,.pdf,.docx,.pptx,.xlsx,.csv,.tsv,.json,.jsonl,.xml,.yaml,.yml,.log,.ini,.cfg,.conf,.zip,.png,.jpg,.jpeg,.webp,text/plain,text/markdown,text/html,text/csv,application/pdf,application/json,application/xml,application/zip,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.presentationml.presentation,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,image/png,image/jpeg,image/webp"',
    "attachment-business-document-accept",
)

processing_label = r'''function uploadProcessingLabel(file,result,index,total){const docs=Number(result&&result.document_count||0),images=Number(result&&result.image_count||0),warnings=Array.isArray(result&&result.warnings)?result.warnings.length:0;const semantic=docs>0?(docs+' document'+(docs===1?'':'s')+' parsed'):(images>0?'image stored · vision unavailable':'validated');return 'Processed '+index+'/'+total+': '+file.name+' · '+semantic+(warnings?' · '+warnings+' warning'+(warnings===1?'':'s'):'')}
'''
html = _replace_once(
    html,
    "async function sendMsg(){",
    processing_label + "async function sendMsg(){",
    "attachment-processing-label",
)

html = _replace_once(
    html,
    "const directUi=state.requestMode==='chat'&&document.getElementById('fmt').value==='source';const pending=addMessage('WorkSpace',files.length?'Uploading and validating files…':'Queued…','',{answer:'',ui_route:directUi?'direct_chat':'workflow',stages:directUi?[]:[{label:'Research',status:'queued'},{label:'Presentation',status:'queued'},{label:'Human Report',status:'queued'}],artifacts:[]});",
    "const directUi=state.requestMode==='chat'&&document.getElementById('fmt').value==='source';const pending=addMessage('WorkSpace',files.length?'Uploading and processing files locally…':(libraryIds.length?'Preparing attached library files…':'Queued…'),'',{answer:'',ui_route:directUi?'direct_chat':'workflow',stages:directUi?[]:[{label:'Research',status:'queued'},{label:'Presentation',status:'queued'},{label:'Human Report',status:'queued'}],artifacts:[]});",
    "attachment-processing-pending-state",
)

html = _replace_once(
    html,
    "const result=await uploadOne(files[i]);uploadIds.push(result.upload_id)}const d=await api('/api/chat'",
    "const result=await uploadOne(files[i]);uploadIds.push(result.upload_id);pending.querySelector('.bubble').textContent=uploadProcessingLabel(files[i],result,i+1,files.length)}if(uploadIds.length)pending.querySelector('.bubble').textContent='Attachments processed locally. Retrieving relevant content for this request…';const d=await api('/api/chat'",
    "attachment-processing-retrieval-state",
)

WORKSPACE_HTML_V18 = html
