import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { createRequire } from 'node:module';
import { chromium } from 'playwright';
import AxeBuilder from '@axe-core/playwright';
const require=createRequire(import.meta.url), ROOT=path.resolve(import.meta.dirname,'..');
const {fileForRoute}=require('../tools/structured-data-utils');
const expected=['modernizare-microintreprinderi-ne-2','autoconsum-institutii-publice','e-drive','dr12-afir','dr14-afir','diaspora-investeste-acasa','fondul-modernizare-pc1-stocare','fondul-modernizare-pc1-stocare-entitati-publice','pro-infra','pocidif-21','dr18-afir','e-move-ro','e-mobility-ro','digitalizare-imm'];
const programs=require('../config/seo-programs.json').programs;
const mime={'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml','.json':'application/json','.webp':'image/webp','.woff2':'font/woff2'};
const server=http.createServer((req,res)=>{const u=new URL(req.url,'http://localhost').pathname;const f=path.extname(u)?path.join(ROOT,u):fileForRoute(ROOT,u);if(!f.startsWith(ROOT)||!fs.existsSync(f)){res.writeHead(404).end();return;}res.setHeader('Content-Type',mime[path.extname(f)]||'application/octet-stream');fs.createReadStream(f).pipe(res);});
const remote=process.argv.find(x=>x.startsWith('--base='))?.slice(7);
if(!remote)await new Promise(r=>server.listen(0,'127.0.0.1',r));
const base=remote||`http://127.0.0.1:${server.address().port}`;
const browser=await chromium.launch();
const out=path.join(ROOT,'.codex','homepage14-screens');fs.mkdirSync(out,{recursive:true});
try {
 for(const width of [320,390,768,1440]){
  const context=await browser.newContext({viewport:{width,height:960},reducedMotion:'reduce'});
  if(!remote)await context.route('**/*',r=>new URL(r.request().url()).origin===base?r.continue():r.abort());
  const page=await context.newPage();await page.goto(base+'/');await page.evaluate(()=>document.fonts.ready);
  assert.deepEqual(await page.locator('[data-priority-slide]').evaluateAll(es=>es.map(e=>e.dataset.programId)),expected);
  assert.deepEqual(await page.locator('#hero [data-hero-program-item]').evaluateAll(es=>es.map(e=>e.dataset.programId)),expected);
  for(const [i,id]of expected.entries()){
   const slide=page.locator('[data-priority-slide][aria-hidden="false"]');
   assert.equal(await slide.getAttribute('data-program-id'),id);
   assert.equal(await slide.locator('.priority-program-link').getAttribute('href'),programs.find(p=>p.id===id).pageUrl);
   await slide.scrollIntoViewIfNeeded();
   const boxes=await slide.evaluate(el=>{const art=el.querySelector('.priority-program-art').getBoundingClientRect();return {overflow:document.documentElement.scrollWidth>innerWidth+1,overlaps:[...el.children].filter(x=>!x.classList.contains('priority-program-art')).some(x=>{const b=x.getBoundingClientRect();return b.right>art.left+2&&b.left<art.right-2&&b.bottom>art.top+2&&b.top<art.bottom-2})}});
   assert.equal(boxes.overflow,false,`${width}/${id}: horizontal overflow`);
   assert.equal(boxes.overlaps,false,`${width}/${id}: illustration overlaps copy`);
   if(width===1440||width===390)await slide.screenshot({path:path.join(out,`${width}-${i+1}-${id}.png`)});
   await page.locator('[data-priority-next]').click();
  }
  assert.equal(await page.locator('[data-priority-slide][aria-hidden="false"]').getAttribute('data-program-id'),expected[0]);
  await page.locator('[data-priority-viewport]').focus();await page.keyboard.press('ArrowLeft');
  assert.equal(await page.locator('[data-priority-slide][aria-hidden="false"]').getAttribute('data-program-id'),expected.at(-1));
  for(const id of expected){const link=page.locator(`#hero [data-hero-program-item][data-program-id="${id}"]`);await link.focus();assert.equal(await page.locator('[data-hero-program-link]').getAttribute('href'),programs.find(p=>p.id===id).pageUrl);}
  const axe=await new AxeBuilder({page}).include('#hero').include('#priority-programs').withTags(['wcag2a','wcag2aa','wcag21aa','wcag22aa']).analyze();
  assert.deepEqual(axe.violations.map(x=>({id:x.id,nodes:x.nodes.map(n=>n.target)})),[],`${width}: homepage accessibility`);
  console.log(`PASS ${width}px: 14 banners/buttons, unique links, keyboard/wrap, no overlap and axe`);
  await context.close();
 }
} finally {await browser.close();if(!remote)await new Promise(r=>server.close(r));}
