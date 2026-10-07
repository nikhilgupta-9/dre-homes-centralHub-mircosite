'use strict';
const { lineAt, countNewlines } = require('./util');

const PHP_BLOCK = /<\?(?!xml)(?:php\b|=)?[\s\S]*?(?:\?>|$)/gi;

/**
 * Split a mixed PHP/HTML file into two views of the SAME line numbering:
 *  - html: PHP blocks replaced by {{PHP}} (so attributes built by PHP are visibly dynamic)
 *  - php : only the PHP code (HTML replaced by blank lines)
 * Also returns blocks (with start lines) so forms printed from inside PHP strings can be found.
 */
function splitPhp(text) {
  let html = '';
  let php = '';
  let last = 0;
  const blocks = [];
  PHP_BLOCK.lastIndex = 0;
  let m;
  while ((m = PHP_BLOCK.exec(text))) {
    if (m[0].length === 0) {
      PHP_BLOCK.lastIndex++;
      continue;
    }
    const before = text.slice(last, m.index);
    const block = m[0];
    html += before + '{{PHP}}' + '\n'.repeat(countNewlines(block));
    php += before.replace(/[^\n]/g, '') + block;
    blocks.push({ index: m.index, line: lineAt(text, m.index), text: block });
    last = m.index + block.length;
  }
  const rest = text.slice(last);
  html += rest;
  php += rest.replace(/[^\n]/g, '');
  return { html, php, blocks, hasPhp: blocks.length > 0 };
}

/** Forms that are printed by PHP code (echo '<form ...>') cannot be edited safely by a tool. */
function phpGeneratedForms(blocks) {
  const out = [];
  for (const b of blocks) {
    const re = /<form\b/gi;
    let m;
    while ((m = re.exec(b.text))) {
      out.push({ line: b.line + countNewlines(b.text.slice(0, m.index)) });
    }
  }
  return out;
}

/** Remove /* *\/ and whole-line // and # comments, keeping line numbers intact. */
function stripPhpComments(code) {
  return code
    .replace(/\/\*[\s\S]*?\*\//g, (s) => '\n'.repeat(countNewlines(s)))
    .replace(/^[ \t]*(?:\/\/|#(?!\[)).*$/gm, '');
}

module.exports = { splitPhp, phpGeneratedForms, stripPhpComments };
