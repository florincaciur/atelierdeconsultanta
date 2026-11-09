const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('playwright');
const { sitemapRoutes, fileForRoute } = require('../tools/structured-data-utils');
const { homepageHeroPrograms, loadProgramConfig } = require('../tools/program-factual-governance');
const heroProgramCount = homepageHeroPrograms(loadProgramConfig().programs).length;
const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(ROOT, 'reports/domain-audit-2026-11-05');
const all = process.argv.includes('--all');
const baseArg = process.argv.find(a=>a.startsWith('--base='));
const viewports = all ? [{width:390,height:844},{width:1440,height:900}] : [
 {width:320,height:640},{width:360,height:740},{width:390,height:844},{width:600,height:800},
 {width:768,height:1024},{width:999,height:768},{width:1024,height:768},
 {width:1366,height:768},{width:1440,height:900},{width:1920,height:900},
 {width:1440,height:900,textZoom:true}
];
const mime={'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml','.png':'image/png','.webp':'image/webp','.json':'application/json'};
const server=http.createServer((req,res)=>{
 const route=decodeURIComponent(new URL(req.url,'http://localhost').pathname);
 let file=path.resolve(ROOT,'.'+route);
 if(!file.startsWith(ROOT+path.sep)&&file!==ROOT){res.writeHead(403);return res.end();}
 if(fs.existsSync(file)&&fs.statSync(file).isDirectory())file=path.join(file,'index.html');
 if(!fs.existsSync(file))file=fileForRoute(ROOT,route);
 if(!fs.existsSync(file)){res.writeHead(404);return res.end();}
 res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream'});fs.createReadStream(file).pipe(res);
});
async function main(){
 fs.mkdirSync(OUT,{recursive:true});
 assert.match(fs.readFileSync(path.join(ROOT,'_headers'),'utf8'),/\/resurse\/descarcari\/\*\.xlsx\r?\n\s+X-Robots-Tag: noindex, follow/);
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const base=baseArg?baseArg.slice(7):`http://127.0.0.1:${server.address().port}`;
 const browser=await chromium.launch();
 const rows=[];
 try {
  if(baseArg) {
   for(const route of ['/resurse/descarcari/calendar-pregatire-depunere.xlsx','/resurse/descarcari/buget-digitalizare-imm.xlsx','/official-guides.json']){
    const response=await fetch(base+route,{redirect:'manual',signal:AbortSignal.timeout(20000)});
    assert.equal(response.status,200,`${route}: resource unavailable`);
    assert.match(response.headers.get('x-robots-tag')||'',/\bnoindex\b/i,`${route}: missing live noindex`);
    await response.body.cancel();
   }
  }
  const routes=all?sitemapRoutes(ROOT):['/'];
  for(const viewport of viewports){
   const page=await browser.newPage({viewport,reducedMotion:'reduce'});
   // Third-party telemetry does not participate in layout verification.
   await page.route(/google-analytics\.com|clarity\.ms|googletagmanager\.com|news\.google\.com/,r=>r.fulfill({status:200,contentType:'text/plain',body:''}));
   for(const route of routes){
    await page.goto(base+route,{waitUntil:'domcontentloaded'});
    await page.locator('h1').first().waitFor();
    await page.evaluate(()=>document.fonts.ready);
    if(viewport.textZoom)await page.addStyleTag({content:'html{font-size:200% !important}'});
    const metrics=await page.evaluate(()=>{
     const box=e=>{if(!e)return null;const b=e.getBoundingClientRect();return {top:b.top,bottom:b.bottom,left:b.left,right:b.right,width:b.width,height:b.height};};
     const main=document.querySelector('main'),hero=document.querySelector('#hero'),h1=document.querySelector('h1'),header=document.querySelector('#navbar');
     const panel=document.querySelector('#hero .homepage-hero__panel');
     const active=document.querySelector('#hero .hero-program-scene.is-active svg');
     const clipped=[];
     for(const el of main?.querySelectorAll('h1,h2,h3,p,a,button,input,select,table')||[]){
      const b=el.getBoundingClientRect(),s=getComputedStyle(el);
      if(!b.width||!b.height||s.display==='none'||s.visibility==='hidden')continue;
      if(b.right>innerWidth+2||b.left< -2){
       const scrollParent=el.closest('.search-quality__table,.table-scroll,.table-wrap,.table-responsive,[role="region"]');
       if(!scrollParent)clipped.push({tag:el.tagName,text:el.textContent.trim().slice(0,80),left:b.left,right:b.right});
      }
     }
     return {overflow:document.documentElement.scrollWidth-innerWidth,h1:box(h1),header:box(header),hero:box(hero),panel:box(panel),scene:box(active),programs:document.querySelectorAll('#hero [data-hero-program-item]').length,clipped:clipped.slice(0,12)};
    });
    const row={route,viewport,...metrics};rows.push(row);
    if(route==='/'){
     assert(metrics.overflow<=1,`${viewport.width}: horizontal overflow`);
     assert(metrics.h1.top>=metrics.header.bottom-1,`${viewport.width}: H1 covered by header`);
     assert(metrics.panel.top>=metrics.header.bottom+8,`${viewport.width}: panel covered by header`);
     assert(metrics.panel.bottom<=metrics.hero.bottom+1,`${viewport.width}: panel clipped by next section`);
     assert.equal(metrics.programs,heroProgramCount);
     assert(metrics.scene.height<=metrics.scene.width+1,`${viewport.width}: distorted scene`);
     if(!all){
      for(let i=0;i<heroProgramCount;i++){
       const link=page.locator('#hero [data-hero-program-item]').nth(i);
       if(i===8) await page.locator('[data-hero-program-next]').press('Enter');
       await link.focus();
       assert.equal(await link.getAttribute('aria-current'),'true',`${viewport.width}px: programul ${i+1} trebuie selectat la focus`);
      }
      await page.evaluate(()=>scrollTo(0,0));
      await page.screenshot({path:path.join(OUT,`hero-${baseArg?'live':'local'}-${viewport.width}${viewport.textZoom?'-zoom':''}.png`),fullPage:false});
     }
    }
   }
   await page.close();
  }
 }finally{await browser.close();await new Promise(r=>server.close(r));}
 fs.writeFileSync(path.join(OUT,all?'responsive.json':`hero-${baseArg?'live':'local'}.json`),JSON.stringify({base,checks:rows.length,rows},null,2));
 console.log(JSON.stringify({checks:rows.length,pages:new Set(rows.map(r=>r.route)).size,overflows:rows.filter(r=>r.overflow>1).map(r=>({route:r.route,width:r.viewport.width,overflow:r.overflow})),clipped:rows.filter(r=>r.clipped.length).map(r=>({route:r.route,width:r.viewport.width,elements:r.clipped})).slice(0,8)}));
}
main().catch(e=>{console.error(e);server.close();process.exitCode=1;});
