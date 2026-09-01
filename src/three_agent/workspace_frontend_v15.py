from __future__ import annotations

from .workspace_frontend_v3 import _replace_once
from .workspace_frontend_v14 import WORKSPACE_HTML_V14


html = WORKSPACE_HTML_V14

# Attachment processing feedback belongs at the latest UI layer. Older frontend
# modules are rollback contracts and must remain byte/patch compatible.
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

WORKSPACE_HTML_V15 = html
