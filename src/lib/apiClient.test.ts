import { describe, it, expect } from 'vitest';
import { parseSse } from './apiClient';

describe('parseSse', () => {
  it('parses complete events and keeps the unfinished remainder', () => {
    const { events, rest } = parseSse('event: start\ndata: {"a":1}\n\nevent: provider\ndata: {"b"');
    expect(events).toEqual([{ event: 'start', data: '{"a":1}' }]);
    expect(rest).toBe('event: provider\ndata: {"b"');
  });

  it('reassembles an event split across chunks', () => {
    const first = parseSse('event: provider\ndata: {"id":');
    const second = parseSse(first.rest + '"vt"}\n\n');
    expect(first.events).toEqual([]);
    expect(second.events).toEqual([{ event: 'provider', data: '{"id":"vt"}' }]);
    expect(second.rest).toBe('');
  });

  it('handles CRLF line endings, multi-line data and default event names', () => {
    const { events } = parseSse('data: line1\r\ndata: line2\r\n\r\n');
    expect(events).toEqual([{ event: 'message', data: 'line1\nline2' }]);
  });

  it('ignores comments and blocks without data', () => {
    expect(parseSse(': keep-alive\n\nevent: ping\n\n').events).toEqual([]);
  });
});
