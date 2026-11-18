import React,{useCallback,useEffect,useMemo,useState} from "react";
import {Background,Controls,MiniMap,ReactFlow,useEdgesState,useNodesState} from "@xyflow/react";
const API="/api/v1";
const colors={observed:"#245b46",hypothesis:"#674b24",confirmed:"#285d87",rejected:"#58343a"};
const columns={component:0,data_source:0,permission:1,method:2,guard:3,sink:4,candidate_path:5,observation:6,evidence:7};
function layout(raw){const counts=new Map();return raw.map(n=>{const k=n.data?.node_type||"other",i=counts.get(k)||0;counts.set(k,i+1);return {...n,position:{x:(columns[k]??8)*250,y:i*135},style:{background:colors[n.data?.assertion]||"#1c2734",color:"#e6edf3",border:"1px solid #42536a",borderRadius:9,width:210,fontSize:12,padding:10}};});}
export default function GraphApp(){
 const params=new URLSearchParams(location.search);
 const [scanId,setScanId]=useState(params.get("scan_id")||"");
 const [nodes,setNodes,onNodesChange]=useNodesState([]),[edges,setEdges,onEdgesChange]=useEdgesState([]);
 const [selected,setSelected]=useState(null),[paths,setPaths]=useState([]),[message,setMessage]=useState("Enter an investigation ID to load its graph."),[busy,setBusy]=useState(false);
 const selectedNode=useMemo(()=>nodes.find(n=>n.id===selected)||null,[nodes,selected]);
 const load=useCallback(async(id=scanId)=>{if(!id.trim()){setMessage("Investigation ID is required.");return;}setBusy(true);try{
   const r=await fetch(`${API}/scans/${encodeURIComponent(id)}/graph`),b=await r.json();if(!r.ok)throw Error(b.detail||b.title||r.statusText);
   setNodes(layout(b.nodes||[]));setEdges((b.edges||[]).map(e=>({...e,style:{stroke:e.data?.assertion==="observed"?"#55a783":e.data?.assertion==="hypothesis"?"#d2a44f":"#6ea8d7",strokeWidth:1.6},labelStyle:{fill:"#cbd5e1",fontSize:10},labelBgStyle:{fill:"#0b1018",fillOpacity:.9}})));
   setPaths(b.candidate_paths||[]);setMessage(`Loaded ${b.nodes?.length||0} nodes and ${b.edges?.length||0} edges.`);
 }catch(e){setMessage(`Graph request failed: ${e.message}`);setNodes([]);setEdges([]);setPaths([]);}finally{setBusy(false);}},[scanId,setNodes,setEdges]);
 const rebuild=useCallback(async()=>{if(!scanId.trim()){setMessage("Investigation ID is required.");return;}setBusy(true);try{
   const r=await fetch(`${API}/scans/${encodeURIComponent(scanId)}/graph/rebuild`,{method:"POST"}),b=await r.json();if(!r.ok)throw Error(b.detail||b.title||r.statusText);
   setMessage(`Rebuilt: ${b.nodes} nodes, ${b.edges} edges, ${b.candidate_paths} candidate paths.`);await load(scanId);
 }catch(e){setMessage(`Graph rebuild failed: ${e.message}`);}finally{setBusy(false);}},[scanId,load]);
 useEffect(()=>{if(params.get("scan_id"))load(params.get("scan_id"));},[]);
 return <div className="app-shell">
  <header className="topbar"><div><div className="eyebrow">MOBIUS / INVESTIGATION INTELLIGENCE</div><h1>Attack Graph</h1></div><a href="/ui">War Room</a></header>
  <main className="layout"><aside className="sidebar">
   <label htmlFor="scan-id">INVESTIGATION ID</label><input id="scan-id" value={scanId} onChange={e=>setScanId(e.target.value)} placeholder="scn_…"/>
   <div className="actions"><button disabled={busy} onClick={()=>load()}>Load graph</button><button disabled={busy} onClick={rebuild}>Rebuild graph</button></div>
   <p className="status">{message}</p>
   <div className="legend"><div><i className="observed"/>Observed</div><div><i className="hypothesis"/>Hypothesis</div><div><i className="confirmed"/>Confirmed</div><div><i className="rejected"/>Rejected</div></div>
   <h2>CANDIDATE PATHS</h2>
   {paths.length?paths.map(p=><button className="path-card" key={p.id} onClick={()=>setSelected(p.id)}><strong>{p.label}</strong><span>{p.missing_proof?.length||0} proof gaps</span><small>{(p.missing_proof||[]).join(" · ")}</small></button>):<p className="muted">No persisted candidate paths.</p>}
   {selectedNode&&<div className="inspector"><h2>SELECTED NODE</h2><strong>{selectedNode.data?.label}</strong><div className="meta">{selectedNode.data?.node_type} · {selectedNode.data?.assertion}</div><div className="meta">{selectedNode.data?.ref||"no ref"}</div><h3>EVIDENCE REFERENCES</h3>{(selectedNode.data?.evidence_refs||[]).map(ref=><code key={ref}>{ref}</code>)}<pre>{JSON.stringify(selectedNode.data?.attributes||{},null,2)}</pre></div>}
  </aside><section className="graph-area"><div className="graph-note">Edges preserve relation, assertion level and evidence provenance. A candidate path is not a confirmed vulnerability.</div>
   <div className="flow-wrap"><ReactFlow nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onNodeClick={(_,n)=>setSelected(n.id)} fitView fitViewOptions={{padding:.18}} minZoom={.1} maxZoom={1.7} proOptions={{hideAttribution:true}}><Background color="#263445" gap={22}/><MiniMap nodeColor={n=>colors[n.data?.assertion]||"#334155"}/><Controls/></ReactFlow>{!nodes.length&&<div className="empty-state">No graph data. Load an investigation, then rebuild its graph.</div>}</div>
  </section></main></div>;
}
