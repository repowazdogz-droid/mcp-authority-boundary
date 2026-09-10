/**
 * Complete parser for the deliberately small SQL language this fixture accepts:
 * SELECT (* | identifier (, identifier)*) FROM identifier (. identifier)? ;?
 *
 * Every token must be consumed. No functions, aliases, joins, expressions,
 * comments, quoted identifiers or other statements are part of this language.
 * Unsupported SQL is refused; this is not a parser for general SQL.
 */
export interface SelectQuery {
  table: string;
  columns: readonly string[] | '*';
  sql: string;
}

/** Fixed fixture schema. New tables/columns require an explicit adapter change. */
export const TABLE_COLUMNS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  'analytics.metrics': Object.freeze(['day', 'visits']),
  'crm.customers': Object.freeze(['id', 'email']),
});

const RESERVED = new Set(['select', 'from', 'where', 'join', 'union', 'into', 'as',
  'delete', 'update', 'insert', 'drop', 'alter', 'create', 'with', 'limit', 'order',
  'group', 'having', 'on', 'and', 'or', 'distinct']);

export function parseSelect(raw: unknown): SelectQuery | null {
  if (typeof raw !== 'string' || raw.length > 16384) return null;
  const tokens: string[] = [];
  for (let i = 0; i < raw.length;) {
    const c = raw[i]!;
    if (' \t\r\n'.includes(c)) { i++; continue; }
    if (/[A-Za-z_]/.test(c)) {
      let end = i + 1;
      while (end < raw.length && /[A-Za-z0-9_]/.test(raw[end]!)) end++;
      tokens.push(raw.slice(i, end).toLowerCase());
      i = end;
    } else if ('*,.;'.includes(c)) {
      tokens.push(c); i++;
    } else return null;
  }
  let at = 0;
  const take = (t: string) => tokens[at] === t ? (at++, true) : false;
  const identifier = (): string | null => {
    const t = tokens[at];
    if (!t || !/^[a-z_][a-z0-9_]*$/.test(t) || RESERVED.has(t)) return null;
    at++;
    return t;
  };
  if (!take('select')) return null;
  let columns: string[] | '*';
  if (take('*')) columns = '*';
  else {
    const first = identifier();
    if (first === null) return null;
    columns = [first];
    while (take(',')) {
      const column = identifier();
      if (column === null) return null;
      columns.push(column);
    }
  }
  if (!take('from')) return null;
  let table = identifier();
  if (table === null) return null;
  if (take('.')) {
    const name = identifier();
    if (name === null) return null;
    table += '.' + name;
  }
  take(';');
  if (at !== tokens.length) return null;
  return { table, columns, sql: `SELECT ${columns === '*' ? '*' : columns.join(', ')} FROM ${table}` };
}
