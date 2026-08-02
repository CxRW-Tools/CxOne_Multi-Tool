#!/usr/bin/env python3
"""
Checkmarx One Multi-Tool — local UI.

A small, dependency-free web UI (Python stdlib only) for Solution Engineers to
authenticate and run the most common tenant actions with a dry-run toggle and
live output. Natural-language via Claude remains the primary, richer interface;
this is a convenient panel for auth + frequent tasks.

Run:   python multitool.py ui          (or: python ui.py)
Then open the printed http://127.0.0.1:PORT URL in a browser.

Security: binds to localhost only. Credentials are entered by you into your own
local server, held in memory for the session, never written to disk, never logged,
never placed in a URL. Purge requires typing the tenant name to confirm.
"""

from __future__ import annotations

import io
import json
import logging
import threading
import webbrowser
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cxone import CxConfig, ApiClient
from iam import IamManager
from applications import ApplicationManager
from onboard import OnboardManager
from purge import TenantPurger

# Single-session state (localhost, single user).
SESSION: dict = {"cfg": None, "api": None}


@contextmanager
def capture_logs():
    """Collect log records emitted during an action to return them to the UI.

    Leaves global logging state exactly as it found it: the previous level of
    the 'cxone' logger is saved and restored (it used to be forced to INFO and
    left that way, silently overriding e.g. a --debug session)."""
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger("cxone")
    prev_level = root.level
    if root.getEffectiveLevel() > logging.INFO:
        root.setLevel(logging.INFO)  # capture at least INFO for the panel
    root.addHandler(h)
    try:
        yield buf
    finally:
        root.removeHandler(h)
        root.setLevel(prev_level)


def _require_auth():
    if not SESSION.get("api"):
        raise PermissionError("Not authenticated")
    return SESSION["api"]


# --------------------------------------------------------------- action handlers
def act_auth(body):
    cfg = CxConfig(
        base_url=(body.get("base_url") or "").rstrip("/"),
        tenant_name=body.get("tenant") or "",
        api_key=body.get("api_key") or "",
        iam_base_url=(body.get("iam_base_url") or "").rstrip("/") or None,
        github_token=body.get("github_token") or None,
    )
    api = ApiClient(cfg)
    api.auth.token()  # force a real token fetch; raises on bad creds
    SESSION["cfg"], SESSION["api"] = cfg, api
    return {"ok": True, "tenant": cfg.tenant_name}


def act_logout(_):
    SESSION["cfg"] = SESSION["api"] = None
    return {"ok": True}


def act_state(_):
    cfg = SESSION.get("cfg")
    return {"authed": bool(cfg), "tenant": cfg.tenant_name if cfg else None,
            "dry_run": cfg.dry_run if cfg else True}


def act_set_dryrun(body):
    cfg = SESSION.get("cfg")
    if cfg:
        cfg.dry_run = bool(body.get("dry_run", True))
    return {"ok": True, "dry_run": cfg.dry_run if cfg else True}


def act_list_groups(_):
    return {"items": [{"id": g.get("id"), "name": g.get("name")}
                      for g in IamManager(_require_auth()).list_groups()]}


def act_create_group(body):
    IamManager(_require_auth()).create_group(body["name"])
    return {"ok": True}


def act_list_users(_):
    api = _require_auth()
    users = api.get("users", params={"max": 1000}, use_iam=True) or []
    return {"items": [{"username": u.get("username"), "email": u.get("email")} for u in users]}


def act_create_user(body):
    IamManager(_require_auth()).create_user(
        username=body["username"], email=body["email"],
        first_name=body.get("first_name", ""), last_name=body.get("last_name", ""),
        password=body.get("password") or None,
        groups=[g for g in (body.get("groups") or "").split(",") if g.strip()],
    )
    return {"ok": True}


def act_list_apps(_):
    return {"items": [{"id": a.get("id"), "name": a.get("name"), "criticality": a.get("criticality")}
                      for a in ApplicationManager(_require_auth()).list_applications()]}


def act_create_app(body):
    ApplicationManager(_require_auth()).create_application({
        "name": body["name"], "description": body.get("description", ""),
        "criticality": int(body.get("criticality", 3)), "project_tag": body.get("project_tag") or None,
    })
    return {"ok": True}


def act_list_projects(_):
    return {"items": [{"id": p.get("id"), "name": p.get("name")}
                      for p in OnboardManager(_require_auth()).list_projects()]}


def act_onboard_github(body):
    api = _require_auth()
    repos = [r.strip() for r in (body.get("repos") or "").split(",") if r.strip()]
    groups = [g.strip() for g in (body.get("groups") or "").split(",") if g.strip()]
    OnboardManager(api).onboard_github([
        {"type": "scm", "scm_type": "github", "organization": body["org"],
         "repository": r, "main_branch": body.get("branch") or None, "groups": groups}
        for r in repos
    ])
    return {"ok": True}


def act_scan(body):
    from ops.run import run_scan
    cfg = SESSION["cfg"]
    if body.get("mode") == "names":
        run_scan(cfg, project_names=body.get("names"))
    else:
        run_scan(cfg, auto=True, percentage=int(body.get("percentage", 20)),
                 min_projects=int(body.get("min_projects", 2)))
    return {"ok": True}


def act_triage(body):
    from ops.run import run_triage
    run_triage(SESSION["cfg"], projects=body["projects"],
               scan_types=body.get("scan_types", "sast,iac,sca"),
               intensity=body.get("intensity", "moderate"))
    return {"ok": True}


def act_purge(body):
    cfg = SESSION["cfg"]
    if not cfg.dry_run and body.get("confirm_tenant") != cfg.tenant_name:
        return {"ok": False, "error": "Confirmation failed: type the tenant name exactly."}
    # The panel always runs the SCOPED purge (tool-created resources only, own
    # user protected). The delete-everything mode (--all) is deliberately CLI-only
    # — it's the sharpest action in the tool and belongs behind the full
    # dry-run/confirm chat protocol, not a button.
    TenantPurger(_require_auth()).purge(include_users=bool(body.get("include_users")))
    return {"ok": True}


ROUTES = {
    "/api/auth": act_auth, "/api/logout": act_logout, "/api/state": act_state,
    "/api/dryrun": act_set_dryrun,
    "/api/groups/list": act_list_groups, "/api/groups/create": act_create_group,
    "/api/users/list": act_list_users, "/api/users/create": act_create_user,
    "/api/apps/list": act_list_apps, "/api/apps/create": act_create_app,
    "/api/projects/list": act_list_projects, "/api/onboard/github": act_onboard_github,
    "/api/scan": act_scan, "/api/triage": act_triage, "/api/purge": act_purge,
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence default access logging
        pass

    def _send(self, code, payload, ctype="application/json"):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, HTML.encode(), "text/html; charset=utf-8")
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        fn = ROUTES.get(self.path)
        if not fn:
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            body = {}
        with capture_logs() as buf:
            try:
                result = fn(body)
            except PermissionError as exc:
                self._send(401, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:
                self._send(200, {"ok": False, "error": str(exc), "log": buf.getvalue()})
                return
        result = dict(result or {})
        result.setdefault("log", buf.getvalue())
        self._send(200, result)


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}"
    print(f"Checkmarx One Multi-Tool UI running at {url}  (Ctrl-C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping UI.")
        httpd.shutdown()


HTML = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Checkmarx One Multi-Tool</title>
<style>
  :root{--bg:#0f1420;--panel:#171e2e;--line:#26304a;--ink:#e7ecf5;--mut:#93a0bd;
        --acc:#5b9cff;--ok:#34d399;--warn:#f59e0b;--err:#f87171;}
  *{box-sizing:border-box} body{margin:0;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;
    background:var(--bg);color:var(--ink)}
  header{display:flex;align-items:center;gap:12px;padding:14px 20px;border-bottom:1px solid var(--line);
    background:var(--panel)}
  header h1{font-size:16px;margin:0;font-weight:600} .pill{font-size:12px;color:var(--mut)}
  .wrap{display:grid;grid-template-columns:300px 1fr;gap:0;min-height:calc(100vh - 52px)}
  .side{border-right:1px solid var(--line);padding:16px;background:var(--panel)}
  .main{padding:18px 22px;overflow:auto}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:14px}
  .card h3{margin:0 0 10px;font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut)}
  label{display:block;font-size:12px;color:var(--mut);margin:8px 0 3px}
  input,select,textarea{width:100%;padding:8px 9px;background:#0e1422;border:1px solid var(--line);
    border-radius:7px;color:var(--ink);font:inherit}
  textarea{min-height:120px;font-family:ui-monospace,Menlo,monospace;font-size:12px}
  button{cursor:pointer;border:0;border-radius:7px;padding:8px 12px;font:inherit;font-weight:600;
    background:var(--acc);color:#06122b;margin-top:10px}
  button.sec{background:#22304d;color:var(--ink)} button.danger{background:var(--err);color:#3a0d0d}
  .nav button{display:block;width:100%;text-align:left;background:transparent;color:var(--ink);
    padding:9px 10px;border-radius:7px;font-weight:500;margin:2px 0}
  .nav button.active{background:#22304d}
  .row{display:flex;gap:10px} .row>*{flex:1}
  .toggle{display:flex;align-items:center;gap:8px;margin-top:10px;font-size:13px}
  .switch{position:relative;width:42px;height:23px}
  .switch input{opacity:0;width:0;height:0}
  .slider{position:absolute;inset:0;background:#33405f;border-radius:20px;transition:.2s}
  .slider:before{content:"";position:absolute;height:17px;width:17px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s}
  input:checked+.slider{background:var(--warn)} input:checked+.slider:before{transform:translateX(19px)}
  .out{background:#0a0f1a;border:1px solid var(--line);border-radius:8px;padding:10px;
    font-family:ui-monospace,Menlo,monospace;font-size:12px;white-space:pre-wrap;min-height:120px;color:#cdd6ea}
  .muted{color:var(--mut);font-size:12px} .ok{color:var(--ok)} .err{color:var(--err)}
  table{width:100%;border-collapse:collapse;font-size:13px} td,th{text-align:left;padding:5px 6px;border-bottom:1px solid var(--line)}
  .hide{display:none}
</style></head><body>
<header><h1>Checkmarx One Multi-Tool</h1>
  <span class="pill" id="who">not connected</span>
  <span style="flex:1"></span>
  <span class="toggle" title="When ON, actions are previewed but never mutate the tenant.">
    <label class="switch"><input type="checkbox" id="dry" checked><span class="slider"></span></label>
    <span id="dryLbl" class="muted">Dry-run ON</span>
  </span>
</header>
<div class="wrap">
  <div class="side">
    <div class="card" id="authCard">
      <h3>Connect</h3>
      <label>Base URL</label><input id="base" placeholder="https://ast.checkmarx.net">
      <label>Tenant</label><input id="tenant" placeholder="your_tenant">
      <label>API key (admin)</label><input id="key" type="password" placeholder="ey...">
      <label>GitHub token (optional)</label><input id="ght" type="password" placeholder="for repo onboarding">
      <button id="connect">Connect</button>
      <button class="sec hide" id="disconnect">Disconnect</button>
      <div class="muted" style="margin-top:8px">Local tool. Credentials stay in memory on your machine.</div>
    </div>
    <div class="nav card">
      <h3>Actions</h3>
      <button data-v="identity" class="active">Identity</button>
      <button data-v="apps">Applications</button>
      <button data-v="projects">Projects &amp; onboarding</button>
      <button data-v="scan">Scan</button>
      <button data-v="triage">Triage</button>
      <button data-v="danger">Teardown</button>
    </div>
  </div>
  <div class="main">
    <div id="identity" class="view">
      <div class="card"><h3>Create group</h3>
        <input id="gName" placeholder="Developers"><button onclick="post('/api/groups/create',{name:val('gName')})">Create group</button>
        <button class="sec" onclick="list('/api/groups/list',['name'])">List groups</button></div>
      <div class="card"><h3>Create user</h3>
        <div class="row"><div><label>Username</label><input id="uUser"></div><div><label>Email</label><input id="uEmail"></div></div>
        <div class="row"><div><label>First</label><input id="uFirst"></div><div><label>Last</label><input id="uLast"></div></div>
        <div class="row"><div><label>Password (demo)</label><input id="uPass"></div><div><label>Groups (comma)</label><input id="uGroups"></div></div>
        <button onclick="post('/api/users/create',{username:val('uUser'),email:val('uEmail'),first_name:val('uFirst'),last_name:val('uLast'),password:val('uPass'),groups:val('uGroups')})">Create user</button>
        <button class="sec" onclick="list('/api/users/list',['username','email'])">List users</button></div>
    </div>
    <div id="apps" class="view hide">
      <div class="card"><h3>Create application</h3>
        <label>Name</label><input id="aName">
        <div class="row"><div><label>Criticality (1-5)</label><input id="aCrit" value="3"></div><div><label>Project tag</label><input id="aTag" placeholder="app:banking"></div></div>
        <label>Description</label><input id="aDesc">
        <button onclick="post('/api/apps/create',{name:val('aName'),criticality:val('aCrit'),project_tag:val('aTag'),description:val('aDesc')})">Create application</button>
        <button class="sec" onclick="list('/api/apps/list',['name','criticality'])">List applications</button></div>
    </div>
    <div id="projects" class="view hide">
      <div class="card"><h3>Onboard from GitHub</h3>
        <div class="row"><div><label>Org</label><input id="oOrg"></div><div><label>Branch</label><input id="oBranch" placeholder="main"></div></div>
        <label>Repos (comma)</label><input id="oRepos" placeholder="WebGoat,juice-shop">
        <label>Groups (comma)</label><input id="oGroups">
        <button onclick="post('/api/onboard/github',{org:val('oOrg'),repos:val('oRepos'),groups:val('oGroups'),branch:val('oBranch')})">Onboard repos</button>
        <button class="sec" onclick="list('/api/projects/list',['name'])">List projects</button></div>
    </div>
    <div id="scan" class="view hide">
      <div class="card"><h3>Run scans</h3>
        <div class="row"><div><label>Percentage of projects</label><input id="sPct" value="20"></div><div><label>Min projects</label><input id="sMin" value="2"></div></div>
        <button onclick="post('/api/scan',{mode:'auto',percentage:val('sPct'),min_projects:val('sMin')})">Scan a random subset</button>
        <label>…or specific project names (comma)</label><input id="sNames">
        <button class="sec" onclick="post('/api/scan',{mode:'names',names:val('sNames')})">Scan named projects</button></div>
    </div>
    <div id="triage" class="view hide">
      <div class="card"><h3>Realistic triage</h3>
        <label>Projects (comma)</label><input id="tProjects">
        <div class="row"><div><label>Scan types</label><input id="tTypes" value="sast,iac,sca"></div>
          <div><label>Intensity</label><select id="tInt"><option>light</option><option>some</option><option selected>moderate</option><option>thorough</option></select></div></div>
        <button onclick="post('/api/triage',{projects:val('tProjects'),scan_types:val('tTypes'),intensity:val('tInt')})">Triage</button>
        <div class="muted" style="margin-top:8px">Realism: high-severity &amp; SAST/SCA triaged first; most low/info left untouched; small chance of exceptions. Intensity maps fuzzy asks ("triage some" → some).</div></div>
    </div>
    <div id="danger" class="view hide">
      <div class="card"><h3>Tear down tenant</h3>
        <div class="muted">Deletes tool-created resources only (scoped). Irreversible. With dry-run ON it only previews. For a real purge, type the tenant name to confirm.</div>
        <div class="row"><div><label>Type tenant name to confirm</label><input id="pConfirm"></div>
          <div><label>Include users</label><select id="pUsers"><option value="">No</option><option value="1">Yes</option></select></div></div>
        <button class="danger" onclick="post('/api/purge',{confirm_tenant:val('pConfirm'),include_users:val('pUsers')})">Purge tenant</button></div>
    </div>
    <div class="card"><h3>Output</h3><div class="out" id="out">Connect to begin.</div></div>
  </div>
</div>
<script>
const $=id=>document.getElementById(id); const val=id=>$(id).value.trim();
const out=$('out');
function show(v){document.querySelectorAll('.view').forEach(e=>e.classList.add('hide'));$(v).classList.remove('hide');
  document.querySelectorAll('.nav button').forEach(b=>b.classList.toggle('active',b.dataset.v===v));}
document.querySelectorAll('.nav button').forEach(b=>b.onclick=()=>show(b.dataset.v));
function render(r){let s='';if(r.error){s+='✗ '+r.error+'\n';}else if(r.ok!==false){s+='✓ done\n';}
  if(r.items){s+='\n'+r.items.map(i=>JSON.stringify(i)).join('\n');}
  if(r.log){s+='\n'+r.log;} out.textContent=s.trim()||'(no output)';
  out.className='out '+(r.error?'err':'');}
async function api(path,body){out.textContent='…';
  try{const res=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});
    return await res.json();}catch(e){return {error:String(e)};}}
async function post(path,body){render(await api(path,body));}
async function list(path,cols){const r=await api(path,{});
  if(r.items){out.innerHTML='<table><tr>'+cols.map(c=>'<th>'+c+'</th>').join('')+'</tr>'+
    r.items.map(i=>'<tr>'+cols.map(c=>'<td>'+(i[c]??'')+'</td>').join('')+'</tr>').join('')+'</table>'
    +(r.items.length?'':'<div class=muted>none</div>');}else{render(r);}}
$('dry').onchange=async()=>{const on=$('dry').checked;$('dryLbl').textContent='Dry-run '+(on?'ON':'OFF');
  $('dryLbl').className=on?'muted':'err';await api('/api/dryrun',{dry_run:on});};
$('connect').onclick=async()=>{const r=await api('/api/auth',{base_url:val('base'),tenant:val('tenant'),
  api_key:val('key'),github_token:val('ght')});
  if(r.ok){$('who').textContent='connected: '+r.tenant;$('who').className='pill ok';
    $('connect').classList.add('hide');$('disconnect').classList.remove('hide');
    await api('/api/dryrun',{dry_run:$('dry').checked});out.textContent='Connected. Dry-run is '+($('dry').checked?'ON':'OFF')+'.';}
  else{render(r);}};
$('disconnect').onclick=async()=>{await api('/api/logout',{});$('who').textContent='not connected';
  $('who').className='pill';$('connect').classList.remove('hide');$('disconnect').classList.add('hide');out.textContent='Disconnected.';};
</script></body></html>"""


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog="ui", description="Run the Multi-Tool local UI")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--no-browser", action="store_true")
    a = p.parse_args(argv)
    serve(a.host, a.port, open_browser=not a.no_browser)
    return 0


if __name__ == "__main__":
    main()
