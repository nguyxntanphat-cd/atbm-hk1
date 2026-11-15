const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

test('Bốn trang dùng script ngoài tương thích CSP và giữ các liên kết tài nguyên', () => {
  for (const file of ['login.html', 'employee.html', 'admin.html', 'tool.html', 'manage.html', 'account.html']) {
    const html = fs.readFileSync(path.join(__dirname, '../public', file), 'utf8');
    assert.match(html, /<meta charset="utf-8">/);
    assert.doesNotMatch(html, /\uFFFD|\son\w+\s*=/);
    const body = html.slice(html.indexOf('<body>'), html.indexOf('<script'));
    assert.ok(!body.includes('?'), 'Không có dấu hỏi do lỗi encoding: ' + file);
    const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]);
    assert.equal(ids.length, new Set(ids).size, file + ': ID không trùng');
    for (const script of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
      assert.equal(script[2], '');
      const src = script[1].match(/src="\/([\w.-]+)"/)[1];
      const code = fs.readFileSync(path.join(__dirname, '../public', src), 'utf8');
      new vm.Script(code, { filename: src });
    }
  }
});

test('Hộp thư hiển thị payload HTML như văn bản và xoá bản rõ khi đổi passphrase', async () => {
  class Element {
    constructor(tag) { this.tag = tag; this.children = []; this.events = {}; this.textContent = ''; this.value = ''; }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    addEventListener(name, handler) { this.events[name] = handler; }
    set innerHTML(_) { throw Error('Không được dùng innerHTML cho dữ liệu hộp thư.'); }
  }
  const nodes = Object.fromEntries(['pass', 'auto', 'tb', 'listStatus', 'view', 'vt'].map(id => [id, new Element(id)]));
  const payload = '<img src=x onerror="alert(document.cookie)">';
  const context = vm.createContext({
    document: { getElementById: id => nodes[id], createElement: tag => new Element(tag), createTextNode: value => value },
    App: {
      async request(route) {
        if (route.startsWith('/api/list')) return { documents: [{ id: '1794737203890-abcdef', sender: payload,
          title: payload, category: 'Khác', filename: 'example.txt', time: new Date().toISOString(), size: 10 }], skipped: 0 };
        return { filename: 'example.txt', data: Buffer.from(payload).toString('base64'), legacy: false };
      },
      bytes: value => Buffer.from(value, 'base64'), download() {}
    },
    window: { addEventListener() {} }, TextDecoder, setTimeout() {}, clearTimeout() {}, setInterval() {}, clearInterval() {}
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../public/admin.js'), 'utf8'), context);
  await new Promise(resolve => setImmediate(resolve));
  const row = nodes.tb.children[0];
  assert.equal(row.children[1].textContent, payload);
  assert.equal(row.children[3].textContent, payload);
  assert.ok(row.children.every(cell => cell.tag === 'td'));
  nodes.pass.value = 'boss123';
  await context.viewDoc('1794737203890-abcdef');
  assert.equal(nodes.view.textContent, payload);
  assert.equal(vm.runInContext('cache.size', context), 1);
  nodes.pass.events.input();
  assert.equal(nodes.view.textContent, '');
  assert.equal(vm.runInContext('cache.size', context), 0);
});
