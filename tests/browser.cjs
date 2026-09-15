const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const base = process.env.LAB_TEST_URL || 'http://127.0.0.1:5050';
(async () => {
  fs.mkdirSync('test-results', {recursive:true});
  const browser = await chromium.launch({headless:true,channel:process.env.BROWSER_CHANNEL || 'msedge'});
  try {
    const context = await browser.newContext({viewport:{width:1440,height:1000}});
    const page = await context.newPage();
    const errors=[]; page.on('pageerror', e=>errors.push(e.message));
    await page.goto(base);
    await page.evaluate(()=>{localStorage.setItem('cyberlab:fundamentals:v1','[2,3,99]');localStorage.removeItem('cyberforge:lab:v1');});
    await page.reload();
    assert.equal(await page.locator('#view-intro').isVisible(),true);
    await page.screenshot({path:'test-results/cyberforge-intro.png',fullPage:true});
    await page.locator('#btn-enter-forge').click();
    await page.waitForSelector('#view-dashboard.active');
    assert.equal(await page.locator('.module-card').count(),15);
    assert.equal(await page.locator('#stat-completed-num').innerText(),'2');
    for(let id=1;id<=15;id++) {
      await page.locator(`.module-card[data-id="${id}"] button`).click();
      await page.waitForSelector('#view-mission.active');
      assert.ok((await page.locator('#mission-command').innerText()).length>10);
      assert.ok(await page.locator('#mission-flags-table tr').count()>=3);
      await page.locator('#hint-accordion summary').click();
      assert.equal(await page.locator('#hint-accordion').getAttribute('open'),'');
      await page.locator('#btn-back-dash').click();
    }
    await page.locator('.module-card[data-id="1"] button').click();
    await page.locator('#mission-answer-input').fill('closed');
    await page.locator('#mission-submit-btn').click();
    await page.waitForSelector('#mission-feedback.error');
    await page.locator('#mission-answer-input').fill('open');
    await page.locator('#mission-submit-btn').click();
    await page.waitForSelector('#mission-feedback.success');
    await page.reload();
    await page.locator('#btn-back-dash').click();
    await page.waitForSelector('#view-dashboard.active');
    assert.equal(await page.locator('#stat-completed-num').innerText(),'3');
    await page.screenshot({path:'test-results/cyberforge-dashboard.png',fullPage:true});
    await page.route('**/api/verify',async route=>{
      await new Promise(resolve=>setTimeout(resolve,500));
      await route.fulfill({json:{correct:true,message:'Previous mission result'}});
    });
    await page.locator('.module-card[data-id="1"] button').click();
    await page.locator('#mission-answer-input').fill('open');
    await page.locator('#mission-submit-btn').click();
    await page.locator('#mission-next-btn').click();
    await page.waitForFunction(()=>!document.getElementById('mission-submit-btn').disabled);
    assert.ok(!(await page.locator('#mission-feedback').innerText()).includes('Previous mission result'));
    await page.unrouteAll({behavior:'wait'});
    await page.setViewportSize({width:390,height:844});
    for(const hash of ['#intro','#dashboard','#task-9']) {
      await page.goto(base+'/'+hash);
      await page.waitForFunction(()=>document.querySelectorAll('.view-container.active').length===1);
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    }
    await page.screenshot({path:'test-results/cyberforge-mobile.png',fullPage:true});
    const remote=await context.newPage();
    await remote.route('http://192.0.2.123/**',async route=>{
      const url=new URL(route.request().url());
      if(url.pathname==='/api/health') return route.fulfill({json:{status:'partial',services:{22:false}}});
      const response=await context.request.get(base+url.pathname); await route.fulfill({response});
    });
    await remote.goto('http://192.0.2.123/#task-9');
    assert.ok((await remote.locator('#mission-command').innerText()).includes('192.0.2.123'));
    await remote.locator('#copy-ip').click();
    await remote.waitForFunction(()=>document.getElementById('toast').textContent==='Copied to clipboard');
    await remote.waitForFunction(()=>document.getElementById('mission-status-pill').textContent==='Partial');
    await page.goto(base+'/#dashboard');
    page.once('dialog',d=>d.accept()); await page.locator('#reset-progress').click();
    await page.reload();
    assert.equal(await page.locator('#stat-completed-num').innerText(),'0');
    assert.deepEqual(errors,[]);
    await remote.unrouteAll({behavior:'wait'});
    console.log('PASS: 15 missions, three views, legacy progress, reset persistence, verification, delayed-response navigation, dynamic IP, clipboard, health, mobile layouts.');
    await context.close();
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
