#!/usr/bin/env python3
"""Run site/index.html's own script against a stub DOM and check what it renders.

`node --check` proves the page parses. It does not prove the page WORKS, and the
difference is not academic: a second `headHtml` further down the file hoisted over the
first, so the terminal's whole head area silently rendered nothing, and the parse was
perfectly valid. The same class of bug once left every platform stuck on "loading
reference data" because one parameter was missing a key.

So this loads the real script, hands it the smallest DOM it will accept, points fetch at
the real bundles in site/data/, and asserts on the HTML that comes out.

Node is OPTIONAL. The pipeline needs python3 and pdftotext and that does not change --
without node this prints a line and exits 0, because a check you cannot run is not a
reason to fail a build.

  python3 tools/check_page.py
"""
import json, os, re, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, 'site/index.html')

SHIM = r'''
const fs=require('fs'), path=require('path');
class El{
  constructor(tag='div',id=''){this.tagName=tag;this.id=id;this._html='';this.textContent='';
    this.classList={_s:new Set(),add(c){this._s.add(c)},remove(c){this._s.delete(c)},
      toggle(c){this._s.has(c)?this._s.delete(c):this._s.add(c)},contains(c){return this._s.has(c)}};
    this.dataset={};this.style={};this.hidden=false;this.children=[];
    this.scrollTop=0;this.scrollHeight=1000;this.clientHeight=600;this.offsetWidth=1}
  set innerHTML(v){this._html=String(v)} get innerHTML(){return this._html}
  getBoundingClientRect(){return {height:23,width:600,top:0,left:0}}
  querySelector(sel){return ROWS[sel]||null} querySelectorAll(){return []}
  closest(){return null} focus(){} scrollIntoView(){} addEventListener(){}
  removeEventListener(){} appendChild(c){this.children.push(c);return c}
  removeChild(c){return c} select(){} setAttribute(){} getAttribute(){return null}
  insertAdjacentHTML(){}
}
const ROWS={'.li':new El('div')};          // a probe row, so the row measurement works
const NODES={};
const mk=id=>NODES[id]||(NODES[id]=new El('div',id));
global.document={getElementById:id=>mk(id),
  querySelector:sel=>sel.startsWith('#')?mk(sel.slice(1)):(ROWS[sel]||null),
  querySelectorAll:()=>[], createElement:t=>new El(t),
  addEventListener:()=>{}, removeEventListener:()=>{},
  body:new El('body'), documentElement:new El('html'), execCommand:()=>true,
  activeElement:null};
global.window=global; global.self=global;
global.matchMedia=q=>({matches:q.includes('min-width'),addEventListener(){},addListener(){}});
global.localStorage={_d:{},getItem(k){return this._d[k]??null},
  setItem(k,v){this._d[k]=v},removeItem(k){delete this._d[k]}};
global.addEventListener=()=>{}; global.removeEventListener=()=>{};
global.requestAnimationFrame=f=>f(); global.setTimeout=()=>0; global.clearTimeout=()=>{};
global.navigator={clipboard:{writeText:async()=>{}},userAgent:'node'};
global.location={hash:'',search:'',href:'http://localhost/'};
global.history={replaceState(){}};
global.fetch=async(u)=>{
  const m=/data\/([^?]+)\.json/.exec(u);
  if(!m)throw new Error('unexpected fetch '+u);
  const f=path.join(DATA_DIR,m[1]+'.json');
  if(!fs.existsSync(f))return {ok:false,status:404};
  return {ok:true,status:200,json:async()=>JSON.parse(fs.readFileSync(f,'utf8'))};
};
'''

DRIVE = r'''
const fails=[];
const ok=(name,got,want)=>{
  const g=JSON.stringify(got),w=JSON.stringify(want);
  if(g!==w)fails.push(`  ${name}: got ${g}, want ${w}`);
  else console.log(`  ok   ${name}`);
};
(async()=>{
  const {S,DATA,LOADERR,PRODUCTS,load,renderTerm,slashRun}=api;
  const head=()=>NODES['hist'].innerHTML, live=()=>NODES['live'].innerHTML;

  await load('fortios');
  ok('a bundle loads and knows which build it is', DATA.fortios.from, 'fortios');
  ok('it has sections', DATA.fortios.secs.length>1000, true);

  S.q=''; S.reply=null; renderTerm(true);
  ok('an empty prompt shows the banner', /class="banner"/.test(head()), true);

  S.q='diag sniffer'; renderTerm(true);
  ok('typing gives the screen to the matches', head(), '');
  ok('the listing renders rows', (live().match(/class="li/g)||[]).length>8, true);
  ok('more rows than the old fixed 14', api.LIVE_N>14, true);

  // the match marks what matched, not the word it landed in
  S.q='dhcp'; renderTerm(true);
  const marks=[...live().matchAll(/<mark>([^<]*)<\/mark>/g)].map(m=>m[1].toLowerCase());
  ok('every highlight is the query, not the whole word',
     marks.length>0&&marks.every(m=>m==='dhcp'), true);

  // a slash reply is the one thing kept above the prompt
  S.q=''; slashRun('/ver'); renderTerm(true);
  ok('a slash reply renders', /class="reply"/.test(head()), true);
  ok('/ver lists only the selected platform',
     S.reply.lines.every(l=>!/\b(FSW|FAZ|FMG)\b/.test(l)), true);
  slashRun('/clear'); renderTerm(true);
  ok('/clear drops the reply', S.reply, null);

  // switching build: the bug was load() keying its cache by PLATFORM, so a switch made
  // while the previous build was still in flight was handed the wrong promise
  S.ver={}; delete DATA.fortios;
  const inflight=load('fortios');
  S.ver={fortios:'8.0.1'};
  const second=load('fortios');
  await Promise.all([inflight,second]);
  ok('a build switch mid-flight lands on the build asked for',
     DATA.fortios.from, 'fortios-8.0');
  S.ver={fortios:'7.6.7'};
  await load('fortios');
  ok('and switching back works', DATA.fortios.from, 'fortios');

  // a build that cannot be fetched must not poison the platform for good
  PRODUCTS[0].vers.push({v:'9.9.9',f:'does-not-exist',src:'test'});
  S.ver={fortios:'9.9.9'};
  try{ await load('fortios'); }catch(e){}
  ok('a failed build is reported, not silent', /404/.test(LOADERR.fortios||''), true);
  S.ver={fortios:'7.6.7'};
  await load('fortios');
  ok('and the platform recovers afterwards', DATA.fortios.from, 'fortios');
  PRODUCTS[0].vers.pop();

  if(fails.length){console.log('\nFAIL\n'+fails.join('\n'));process.exit(1)}
  console.log('\nselftest: all good');
})().catch(e=>{console.log('THREW: '+e.stack.split('\n').slice(0,4).join('\n'));process.exit(1)});
'''


def main():
    if not shutil.which('node'):
        print('  check_page: node not found -- skipped (the pipeline does not need it)')
        return 0
    html = open(PAGE, encoding='utf-8').read()
    blocks = re.findall(r'<script[^>]*>(.*?)</script>', html, re.S)
    if len(blocks) != 1:
        print(f'  check_page: expected one <script> block, found {len(blocks)}')
        return 1
    body = blocks[0].strip()
    # the page wraps itself in an IIFE; unwrap it so the test can reach the names
    if not (body.startswith('(function(){') and body.endswith('})();')):
        print('  check_page: the script is no longer one IIFE -- update this tool')
        return 1
    body = body[len('(function(){'):-len('})();')]

    d = tempfile.mkdtemp(prefix='check-page-')
    try:
        shim = SHIM.replace('DATA_DIR', json.dumps(os.path.join(ROOT, 'site/data')))
        src = (shim + '\nconst api=new Function(' +
               json.dumps(body + '\n;return {S,DATA,LOADING,LOADERR,PRODUCTS,load,'
                                 'renderTerm,search,items,slashRun,slashList,termHead,'
                                 'liveHtml,measureLive,get LIVE_N(){return LIVE_N}};') +
               ')();\n' + DRIVE)
        run = os.path.join(d, 'run.js')
        open(run, 'w').write(src)
        p = subprocess.run(['node', run], capture_output=True, text=True)
        sys.stdout.write(p.stdout)
        if p.returncode:
            sys.stderr.write(p.stderr)
        return p.returncode
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
