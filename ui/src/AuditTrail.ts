// AuditTrail, the face of cell:cr.audit@2. The audit trail of every node and the keys audit, newest first, live.
// `detail` is a Part: a viewer without cr.audit:detail has no detail on the wire and the column says nothing.
import { AuditTrail } from '../gen/CrAudit.ui';
import type { AuditKind, AuditRow } from '../gen/CrAudit';
import { show } from '@ui/rt';
import { clear, exhaustive, h, num, time } from '@ui/kit/dom';
import { empty, failed, loading, sourcesLine } from '@ui/kit/faces';

export function kindText(k: AuditKind): string {
  switch (k.tag) {
    case 'Call':
      return 'call';
    case 'Grant':
      return 'grant';
    case 'Revoke':
      return 'revoke';
    case 'Approval':
      return 'approval';
    case 'KeyEvent':
      return 'key';
    default:
      return exhaustive(k);
  }
}

function row(r: AuditRow, chain: (id: string) => void): HTMLElement {
  return h(
    'tr',
    { class: r.ok ? '' : 'failed', attrs: { 'data-row': r.id } },
    h('td', { class: 'mono', text: time(r.at_ms) }),
    h('td', {}, h('span', { class: `st ${r.ok ? 'g' : 'r'}` }, h('i'), r.ok ? 'ok' : 'refused')),
    h('td', {}, h('b', { text: `${r.app} ${r.op}` }), h('div', { class: 'sub', text: r.target })),
    h('td', { class: 'mono hide-sm', text: r.actor.length > 20 ? r.actor.slice(0, 16) + '...' : r.actor }),
    h('td', { class: 'hide-sm', text: kindText(r.kind) }),
    h('td', { class: 'mono hide-sm', text: `${r.node}${r.seq > 0n ? ' #' + num(r.seq) : ''}` }),
    h('td', { class: 'hide-sm sub', text: show(r.detail, (d) => d.slice(0, 120)) ?? '' }),
    h('td', { class: 'mono hide-sm' }, r.chain_id === null ? '' : h('button', { class: 'btn quiet', text: r.chain_id.slice(0, 8), title: 'chain id', onclick: () => chain(r.chain_id ?? '') })),
  );
}

export default AuditTrail.render((v) => {
  const body = h('div', {}, loading());
  const search = h('input', { class: 'search', label: 'Search the trail', attrs: { type: 'search', placeholder: 'Search op, target, actor' } });
  const failedOnly = h('button', { pressed: false, text: 'Refused only' });
  search.addEventListener('input', () => v.setProps({ q: search.value.trim() === '' ? null : search.value.trim() }));
  failedOnly.addEventListener('click', () => {
    const on = v.props.only_failed !== true;
    failedOnly.setAttribute('aria-pressed', String(on));
    v.setProps({ only_failed: on });
  });
  v.draw((d, why) => {
    if (d.rows === undefined) return clear(body, why === null ? loading() : failed(why));
    const rows = [...d.rows].sort((a, b) => Number(b.at_ms - a.at_ms));
    const bad = rows.filter((r) => !r.ok).length;
    clear(
      body,
      h(
        'div',
        { class: 'stats' },
        h('div', { class: 'glass ticks stat' }, h('div', { class: 'label' }, h('i'), 'Rows'), h('div', { class: 'num acc', text: num(rows.length) }), h('div', { class: 'sub', text: 'newest first, every node' })),
        h('div', { class: 'glass stat' }, h('div', { class: 'label' }, h('i', { class: 'r' }), 'Refused'), h('div', { class: 'num', text: num(bad) }), h('div', { class: 'sub', text: 'calls a gate said no to' })),
      ),
      rows.length === 0
        ? empty('No rows here.')
        : h(
            'div',
            { class: 'glass tablewrap' },
            h(
              'table',
              {},
              h('thead', {}, h('tr', {}, ...['At', 'Answer', 'Call', 'Actor', 'Kind', 'Node', 'Detail', 'Chain'].map((t, i) => h('th', { class: i >= 3 ? 'hide-sm' : '', text: t })))),
              h('tbody', {}, ...rows.slice(0, 200).map((r) => row(r, v.emit.chain))),
            ),
          ),
      why === null ? null : failed(why),
      sourcesLine(d.sources, why === null),
    );
  });
  return h('section', { class: 'panel', attrs: { 'data-view': 'AuditTrail' } }, h('div', { class: 'toolbar' }, search, h('div', { class: 'pills' }, failedOnly)), body);
});
