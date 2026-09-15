export const dashboardHtml = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DNSid × A2A Protocol Inspector</title>
<style>
  :root { --line:#d9dee7; --muted:#5f6b7a; --text:#172033; --blue:#1769e0; --green:#16845b; --red:#c7354f; }
  * { box-sizing:border-box }
  body { margin:0; min-height:100vh; font:15px/1.5 ui-sans-serif,system-ui,sans-serif; color:var(--text); background:#fff; }
  main { width:min(1040px,calc(100% - 32px)); margin:auto; padding:40px 0 72px; }
  header { margin-bottom:30px; }
  h1 { margin:0; font-size:clamp(28px,4vw,44px); line-height:1.1; letter-spacing:-.035em; }
  h1 span { color:var(--blue) }
  .lede { margin:8px 0 0; color:var(--muted); font-size:17px }
  .agents { display:grid; grid-template-columns:1fr 72px 1fr; align-items:center; margin-bottom:20px; }
  .agent,.composer,.step { border:1px solid var(--line); border-radius:10px; background:#fff; }
  .agent { padding:20px; }
  .agent strong,.agent span,.agent small { display:block; }
  .agent strong { margin-bottom:5px; font-size:18px; }
  .agent span { margin-bottom:3px; }
  .agent small { color:var(--green); }
  .arrow { height:1px; background:var(--blue); position:relative; }
  .arrow:after { content:""; position:absolute; right:0; top:-5px; border:6px solid transparent; border-left-color:var(--blue); }
  .composer { padding:20px; display:grid; grid-template-columns:1fr auto; gap:12px; margin-bottom:26px; background:#f8f9fb; }
  input,button { font:inherit; border-radius:7px; border:1px solid var(--line); color:var(--text); background:#fff; padding:11px 13px; }
  button { border-color:var(--blue); background:var(--blue); color:#fff; font-weight:700; cursor:pointer; padding-inline:22px; }
  button:hover { background:#1258bd } button:disabled { opacity:.55; cursor:wait }
  label.tamper { grid-column:1/3; color:var(--muted); display:flex; gap:9px; align-items:center; }
  input[type=checkbox] { accent-color:var(--red); width:17px; height:17px; }
  .steps { display:grid; gap:14px; }
  .sequence-row { display:grid; grid-template-columns:1fr 72px 1fr; }
  .sequence-row.alice .step { grid-column:1; }
  .sequence-row.bob .step { grid-column:3; }
  .sequence-row.send-right .step { grid-column:1/3; }
  .sequence-row.send-left .step { grid-column:2/4; }
  .step { display:grid; grid-template-columns:44px 1fr auto; gap:14px; align-items:center; padding:16px 18px; }
  .step.pending { opacity:.55 } .step.running { border-color:var(--blue); }
  .step.ok { border-color:#9bcfbd } .step.bad { border-color:#e3a4af; }
  .number { display:grid; place-items:center; width:32px; height:32px; border:1px solid var(--line); border-radius:50%; color:var(--muted); font-weight:800; }
  .ok .number { color:#fff; border-color:var(--green); background:var(--green) } .bad .number { color:#fff; border-color:var(--red); background:var(--red) }
  .step h2 { display:inline; font-size:16px; margin:0 } .step p { color:var(--muted); margin:4px 0 0 }
  .protocols { display:inline-flex; gap:5px; margin-left:8px; vertical-align:2px; }
  .protocol { border-radius:99px; padding:2px 7px; font-size:11px; font-weight:800; }
  .protocol.dnsid { color:#0d6847; background:#e4f4ee; }
  .protocol.a2a { color:#1455aa; background:#e8f1fd; }
  .badge { border:1px solid var(--line); border-radius:99px; padding:3px 9px; color:var(--muted); font-size:11px; font-weight:700; }
  .artifact { grid-column:2/4; border-top:1px solid var(--line); padding-top:12px; margin-top:2px; }
  summary { cursor:pointer; color:var(--blue); }
  .nested { display:grid; gap:8px; margin-top:12px; }
  .nested details { border:1px solid var(--line); border-radius:7px; padding:9px 11px; }
  .nested details summary { color:var(--text); font-weight:600; }
  pre { white-space:pre-wrap; overflow-wrap:anywhere; padding:14px; border:1px solid var(--line); border-radius:7px; background:#f8f9fb; color:#344054; font:12px/1.55 ui-monospace,SFMono-Regular,monospace; max-height:330px; overflow:auto; }
  .result { margin:18px 0 0; padding:16px 18px; border-radius:8px; font-weight:700; display:none; }
  .result.ok { display:block; background:#edf8f4; color:var(--green) } .result.bad { display:block; background:#fff0f2; color:var(--red) }
  @media (max-width:720px) { .agents { grid-template-columns:1fr }.arrow { width:1px; height:30px; margin:auto }.arrow:after { right:-5px; top:auto; bottom:-7px; border-left-color:transparent; border-top-color:var(--blue) }.composer { grid-template-columns:1fr }.composer label.tamper { grid-column:auto }.sequence-row { grid-template-columns:1fr }.sequence-row.alice .step,.sequence-row.bob .step,.sequence-row.send-right .step,.sequence-row.send-left .step { grid-column:1 }.step { grid-template-columns:38px 1fr }.badge { display:none }.artifact { grid-column:2 } }
</style>
</head>
<body>
<main>
  <header><h1>DNSid <span>×</span> A2A</h1><p class="lede">Watch domain identity become authenticated agent traffic.</p></header>
  <section class="agents">
    <div class="agent"><strong>Alice</strong><span>alice.dev.dnsid.test</span><small>DNSid identity ready</small></div>
    <div class="arrow" aria-hidden="true"></div>
    <div class="agent"><strong>Bob</strong><span>bob.dev.dnsid.test</span><small>DNSid identity ready</small></div>
  </section>
  <form class="composer" id="form">
    <input id="message" value="hello from alice.dev.dnsid.test" maxlength="2000" aria-label="Message">
    <button id="send">Send signed A2A</button>
    <label class="tamper"><input type="checkbox" id="tamper"> Tamper with the payload after signing — Bob should reject it</label>
  </form>
  <section class="steps" id="steps"></section>
  <div class="result" id="result" role="status"></div>
</main>
<script>
const definitions = [
  { lane:'alice', title:'Alice verifies Bob', protocols:['DNSid'], summary:'Alice establishes Bob’s domain identity before sending application traffic.' },
  { lane:'alice', title:'Alice fetches Bob’s card, then sends', protocols:['A2A','DNSid'], summary:'Alice fetches Bob’s agent card, signs SendMessage with her DNSid key and sends the request to Bob.' },
  { lane:'bob', title:'Bob receives Alice’s request', protocols:['A2A','DNSid'], summary:'Bob receives the A2A payload together with Alice’s signature envelope.' },
  { lane:'bob', title:'Bob verifies Alice', protocols:['DNSid'], summary:'Before execution, Bob independently verifies Alice’s domain identity and the request signature.' },
  { lane:'bob', title:'Bob executes and replies to Alice', protocols:['A2A'], summary:'Bob executes SendMessage for the verified sender and returns the A2A result to Alice.' },
  { lane:'alice', title:'Alice receives Bob’s reply', protocols:['A2A'], summary:'Alice receives the result, including the DNSid identity Bob authenticated for the caller.' },
];
const steps = document.querySelector('#steps');
const form = document.querySelector('#form');
const button = document.querySelector('#send');
const result = document.querySelector('#result');
let stepElements=[];
function reset() {
  steps.replaceChildren(); stepElements=[];
  definitions.forEach((definition,i) => {
    const row=document.createElement('div'), el=document.createElement('article'), content=document.createElement('div'), title=document.createElement('h2'), protocols=document.createElement('span'), summary=document.createElement('p');
    row.className='sequence-row '+definition.lane; el.className='step pending'; protocols.className='protocols';
    title.textContent=definition.title; summary.textContent=definition.summary;
    for (const protocol of definition.protocols) {
      const badge=document.createElement('span'); badge.className='protocol '+protocol.toLowerCase(); badge.textContent=protocol; protocols.append(badge);
    }
    content.append(title,protocols,summary);
    el.innerHTML='<div class="number">'+(i+1)+'</div>'; el.append(content);
    const status=document.createElement('span'); status.className='badge'; status.textContent='WAITING'; el.append(status);
    row.append(el); steps.append(row); stepElements.push(el);
  });
  result.className='result'; result.textContent='';
}
function finish(i, ok, detail, label, artifactLabel) {
  const el=stepElements[i]; el.className='step '+(ok?'ok':'bad');
  el.querySelector('.number').textContent=ok?'✓':'×'; el.querySelector('.badge').textContent=label || (ok?'COMPLETE':'REJECTED');
  if (detail !== undefined) addArtifact(el,artifactLabel || 'Inspect artifact',detail);
}
function addArtifact(el,label,detail) {
  const d=document.createElement('details'), s=document.createElement('summary'), p=document.createElement('pre');
  d.className='artifact'; s.textContent=label; p.textContent=typeof detail==='string'?detail:JSON.stringify(detail,null,2); d.append(s,p); el.append(d);
}
function addNestedArtifacts(el,label,items) {
  const outer=document.createElement('details'), summary=document.createElement('summary'), nested=document.createElement('div');
  outer.className='artifact'; nested.className='nested'; summary.textContent=label; outer.append(summary,nested);
  for (const [itemLabel,detail] of items) {
    const d=document.createElement('details'), s=document.createElement('summary'), p=document.createElement('pre');
    s.textContent='✓ '+itemLabel; p.textContent=JSON.stringify(detail,null,2); d.append(s,p); nested.append(d);
  }
  el.append(outer);
}
function running(i) { const el=stepElements[i]; el.className='step running'; el.querySelector('.badge').textContent='RUNNING'; }
form.onsubmit = async event => {
  event.preventDefault(); reset(); button.disabled=true; running(0);
  try {
    const response=await fetch('/demo/send',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({target:'bob.dev.dnsid.test',message:document.querySelector('#message').value,tamper:document.querySelector('#tamper').checked})});
    const data=await response.json(); if(!response.ok) throw new Error(data.error || 'Demo request failed');
    finish(0,true,undefined,'VERIFIED');
    addNestedArtifacts(stepElements[0],'Open full DNSid verification',[
      ['DNS record',data.verification.dns],
      ['Entity JWKS and record signature',data.verification.entityKeys],
      ['Operational JWKS',data.verification.operationalKeys],
      ['C2SP lifecycle',data.verification.lifecycle],
      ['Current status',data.verification.status],
    ]);
    finish(1,true,undefined,'SENT');
    addNestedArtifacts(stepElements[1],'Open A2A discovery and signed request',[
      ['Agent card Alice fetched from Bob',data.trace.agentCard],
      ['Signed request Alice sent to Bob',data.trace.request],
    ]);
    finish(2,!!data.trace.response,data.trace.request,'RECEIVED','What arrived at Bob');
    finish(3,data.accepted,undefined,data.accepted?'VERIFIED':'REJECTED');
    addNestedArtifacts(stepElements[3],'Open full DNSid verification',[
      ['DNS record',data.bobVerification.dns],
      ['Entity JWKS and record signature',data.bobVerification.entityKeys],
      ['Operational JWKS',data.bobVerification.operationalKeys],
      ['C2SP lifecycle',data.bobVerification.lifecycle],
      ['Current status',data.bobVerification.status],
    ]);
    addArtifact(stepElements[3],'Open HTTP signature verification',{
      note:data.bobVerification.evidenceNote,
      ...data.bobVerification.request,
    });
    finish(4,data.accepted,data.accepted?data.trace.response:undefined,data.accepted?'SENT':'BLOCKED','A2A response Bob sent');
    finish(5,data.accepted,data.reply || data.error,data.accepted?'RECEIVED':'NO REPLY','A2A reply Alice received');
    const expectedRejection=data.tampered && data.trace.response?.status===401;
    result.className='result '+(data.accepted || expectedRejection?'ok':'bad');
    result.textContent=data.accepted
      ?'✓ Bob accepted Alice as '+data.source+': “'+data.reply+'”'
      :expectedRejection
        ?'✓ Expected rejection: altered bytes no longer match Alice’s DNSid-bound signature.'
        :'Request failed: '+data.error;
  } catch(error) {
    stepElements.forEach((el,i) => { if(el.classList.contains('running')) finish(i,false,String(error),'ERROR'); });
    result.className='result bad'; result.textContent=String(error);
  } finally { button.disabled=false; }
};
reset();
</script>
</body>
</html>`;
