/**
 * Tova Edit (tovaedit.com): lets this site's editors change its words on the page. Added by Tova; safe to keep.
 *
 * What it does: endpoints under /api/tova/ that answer only requests signed by Tova for this one site
 * (Ed25519; Tova's public key and this site's id are written below). It holds no secret and adds no package.
 *
 *   hello   which Payload and database this is, and the names of its collections, so Tova knows the plugin is live
 *   survey  how many documents of each collection have words that appear on the live pages Tova sends (counts only)
 *   read    published documents and globals (for the words, and for building Tova's copy of the site)
 *   get     one document, published and newest, before a change
 *   write   changed words in one document or global, through Payload's Local API, so your hooks,
 *           versions, drafts and revalidation run as if someone saved in the admin; since version 4 also numbers,
 *           yes/no and dates as what they are, and the rows of a list (array, blocks, relationships) in a new order,
 *           copied or removed (a copy has the same fields as the row it copies; nothing new is invented)
 *   schema  what kind of field each field is (names and kinds only, never values), for the collections on Tova's list
 *   create  a new document made as a copy of an existing one (Duplicate, "New post"), published like a save in the admin
 *   doc     unpublish a document (collections with drafts only: it stays as a draft), publish it again (undo), or delete
 *           one. Since version 5 a delete is allowed only for (a) a hidden document (an unpublished draft) in a collection
 *           the owner marked "Can be deleted" in Tova, or (b) a copy Tova made a few minutes ago in the same publish and
 *           named in the request. Anything else is refused, whatever is signed
 *   upload  a new photo for a photo field, into the upload collection the field points at
 *   slugs   the page addresses a collection already uses, so a new page never takes one
 *
 * Which collections: the site's owner chooses in Tova (Settings, "What can editors change?"), and every signed request
 * carries that choice. read, get and write answer only for collections on it; anything else never leaves the site.
 * Never read or written, whatever the choice: fields with their own access rule (read, update or create), at any depth;
 * sign-in collections' secrets (passwords, API keys, sessions; emails are replaced) and Payload's own collections
 * (preferences, locked documents, migrations, jobs). Writes change only text in existing fields (words and link
 * addresses; never relationships, block types, numbers or the shape of a list), and never sign-in collections; anything
 * else is refused. Fields marked hidden: true never leave the site, even in the copy Tova builds. To leave a collection
 * out whatever Tova asks, add its slug to EXCLUDE.
 *
 * Remove it any time: delete this file and the tova() line in your Payload config.
 */
/* eslint-disable */
import type { CollectionSlug, Config, GlobalSlug, Payload, PayloadRequest } from 'payload'

const PLUGIN_VERSION = 5
/** This site in Tova. A request signed for another site is refused. */
const SITE = 'b3e59e06-f585-4270-918e-953b95927cd6'
/** Tova's public keys (Ed25519, base64url). More than one only while Tova changes keys. */
const KEYS: string[] = ['6-dbtoaXQHoIHQFzgsASQpQwFvOb_9oqSHvud76ObsM']
/** Collections Tova should never see. */
const EXCLUDE: string[] = []

/** Collections that are never a site's words (what hello lists as words). */
const NOT_WORDS = /^(payload-.+|form-submissions|search|redirects|exports|imports)$/
/** Payload's own records: never sent, whatever Tova asks. */
const NEVER = /^(payload-(preferences|locked-documents|migrations|jobs|kv|query-presets)|exports|imports)$/
/** Fields Payload adds to sign-in collections: never leave the site. */
const AUTH_FIELD = /^(email|username|hash|salt|resetPassword\w*|loginAttempts|lockUntil|enableAPIKey|apiKey\w*|sessions|_verified|_verificationToken|otp\w*|mfa\w*|totp\w*)$/
/** Fields a write may never set. */
const FIXED = new Set(['id', '_id', 'createdAt', 'updatedAt', '_status', 'globalType'])
const WINDOW_S = 300
/** A copy Tova made may be taken away again for this long after it was made (a publish that fails half way). */
const MADE_WINDOW_MS = 10 * 60_000
const PAGE = 100
const MAX_BODY = 1_000_000
/** A photo goes up as base64 in one request: the one place a bigger body is read (about 6 MB of photo). */
const MAX_UPLOAD = 8_000_000
const IMAGE_TYPES = new Set(['image/webp', 'image/jpeg', 'image/png', 'image/avif', 'image/gif'])
/** The survey looks at this many documents per collection. */
const SURVEY_DOCS = 100

type Doc = Record<string, unknown>
/** Payload's generated types differ per site; Tova reads documents as plain objects. */
const asDoc = (x: unknown) => x as Doc
const b64 = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('')
const reply = (body: unknown, status = 200) => Response.json(body, { status, headers: { 'cache-control': 'no-store' } })

const seen = new Map<string, number>()
async function signedBy(req: PayloadRequest, op: string, body: string): Promise<string | null> {
  const time = Number(req.headers.get('x-tova-time'))
  const nonce = req.headers.get('x-tova-nonce') ?? ''
  const [v, kid, sig] = (req.headers.get('x-tova-signature') ?? '').split('.')
  const now = Date.now() / 1000
  if (v !== 'v1' || !/^[A-Za-z0-9_-]{86}$/.test(sig ?? '') || !/^[A-Za-z0-9_-]{16,64}$/.test(nonce) || !(Math.abs(now - time) <= WINDOW_S)) return 'unsigned'
  const key = KEYS.find((k) => kid && kid.length >= 8 && k.startsWith(kid))
  if (!key) return 'unknown key'
  const digest = hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)))
  const message = ['tova-payload/v1', SITE, req.method?.toUpperCase(), op, String(time), nonce, digest].join('\n')
  const pub = await crypto.subtle.importKey('raw', b64(key), { name: 'Ed25519' }, false, ['verify'])
  const ok = await crypto.subtle.verify({ name: 'Ed25519' }, pub, b64(sig), new TextEncoder().encode(message)).catch(() => false)
  if (!ok) return 'bad signature'
  // The same request twice (within the time window) is refused, as far as this server instance can tell.
  for (const [n, t] of seen) if (t < now - WINDOW_S) seen.delete(n)
  if (seen.has(nonce)) return 'replayed'
  seen.set(nonce, now)
  return null
}

/**
 * What Tova may have, from the signed request: `edit` (words editors see and change) and `build` (only for building
 * Tova's copy of the site). Collections by slug, globals as global:<slug>. No list, nothing is answered.
 */
type Allow = { edit: Set<string>; build: Set<string>; del: Set<string> }
function allowOf(input: Doc): Allow | null {
  const a = input.allow as { edit?: unknown; build?: unknown; del?: unknown } | undefined
  const list = (x: unknown) => new Set(Array.isArray(x) ? x.filter((k): k is string => typeof k === 'string' && k.length <= 80) : [])
  return a && Array.isArray(a.edit) ? { edit: list(a.edit), build: list(a.build), del: list(a.del) } : null
}
const shut = (slug: string) => EXCLUDE.includes(slug) || NEVER.test(slug)
function collections(payload: Payload, mode: 'words' | 'export', allow: Allow) {
  return payload.config.collections.filter((c) => {
    if (shut(c.slug)) return false
    return mode === 'export' ? allow.edit.has(c.slug) || allow.build.has(c.slug) : !c.auth && allow.edit.has(c.slug)
  })
}
const globalAllowed = (slug: string, mode: 'words' | 'export', allow: Allow) =>
  !EXCLUDE.includes(slug) && (allow.edit.has(`global:${slug}`) || (mode === 'export' && allow.build.has(`global:${slug}`)))
const isWords = (payload: Payload, slug: string, allow: Allow) => collections(payload, 'words', allow).some((c) => c.slug === slug)
const hasDrafts = (payload: Payload, slug: string, global = false) =>
  Boolean((global ? payload.config.globals.find((g) => g.slug === slug) : payload.config.collections.find((c) => c.slug === slug))?.versions?.drafts)

/** A sign-in collection's document without anything that signs anyone in (the email becomes a placeholder). */
function safe(doc: Doc, auth: boolean): Doc {
  if (!auth) return doc
  const out = Object.fromEntries(Object.entries(doc).filter(([k]) => !AUTH_FIELD.test(k)))
  return 'email' in doc ? { ...out, email: `user-${String(doc.id)}@tova.invalid` } : out
}

/**
 * Field rules. Tova reads and writes with overrideAccess, which skips a field's own access rule, so a field that has one
 * (read, update or create) is left out of everything Tova sees and refused on write. `hidden: true` fields are also
 * left out, even of the build copy. Both are found from the config, at any depth, by data path.
 */
type Field = {
  type?: string
  name?: string
  access?: Record<string, unknown>
  hidden?: boolean
  localized?: boolean
  hasMany?: boolean
  relationTo?: string | string[]
  options?: (string | { value?: unknown })[]
  fields?: Field[]
  tabs?: Field[]
  blocks?: (string | { slug: string; fields: Field[] })[]
  blockReferences?: (string | { slug: string; fields: Field[] })[]
}
const ruled = (f: Field) => Boolean(f.access && ['read', 'update', 'create'].some((k) => f.access![k]))
/** The fields that sit at one data level: rows, collapsibles and unnamed tabs add no level of their own. */
function level(fields: Field[] | undefined): Field[] {
  const out: Field[] = []
  for (const f of fields ?? []) {
    if (f.type === 'tabs') for (const t of f.tabs ?? []) out.push(...(t.name ? [{ ...t, type: 'group' }] : level(t.fields)))
    else if (f.type === 'row' || f.type === 'collapsible' || (!f.name && f.fields)) out.push(...level(f.fields))
    else if (f.name) out.push(f)
  }
  return out
}
const variants = (payload: Payload, f: Field) =>
  (f.blocks ?? f.blockReferences ?? []).map((b) => (typeof b === 'string' ? (payload.config.blocks as unknown as { slug: string; fields: Field[] }[] | undefined)?.find((x) => x.slug === b) : b)).filter(Boolean) as { slug: string; fields: Field[] }[]
/** The fields of what a value holds, for lists and groups (a block's by its blockType). */
function inner(payload: Payload, f: Field, item: unknown): Field[] {
  if (f.type !== 'blocks') return f.fields ?? []
  return variants(payload, f).find((b) => b.slug === (item as Doc | null)?.blockType)?.fields ?? []
}
/** Leaves out hidden fields, and with `ruledToo` fields that have an access rule. */
function strip(payload: Payload, v: unknown, f: Field, ruledToo: boolean, all: boolean, depth = 0): unknown {
  if (!v || typeof v !== 'object' || depth > 60) return v
  // A localized value read as every locale is { en: …, de: … }.
  if (all && f.localized && !Array.isArray(v) && ['group', 'array', 'blocks'].includes(f.type ?? ''))
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, strip(payload, x, { ...f, localized: false }, ruledToo, all, depth + 1)]))
  if (f.type === 'group') return scrub(payload, v as Doc, f.fields, ruledToo, all, depth + 1)
  if (Array.isArray(v) && (f.type === 'array' || f.type === 'blocks')) return v.map((i) => (i && typeof i === 'object' ? scrub(payload, i as Doc, inner(payload, f, i), ruledToo, all, depth + 1) : i))
  return v
}
function scrub(payload: Payload, doc: Doc, fields: Field[] | undefined, ruledToo: boolean, all: boolean, depth = 0): Doc {
  const out = { ...doc }
  for (const f of level(fields)) {
    const k = f.name as string
    if (!(k in out)) continue
    if (f.hidden === true || (ruledToo && ruled(f))) delete out[k]
    else out[k] = strip(payload, out[k], f, ruledToo, all, depth)
  }
  return out
}
/** True when a field, or anything inside it, has an access rule or is hidden. */
function hasRuled(payload: Payload, fields: Field[] | undefined, depth = 0): boolean {
  if (depth > 60) return true
  return level(fields).some((f) => ruled(f) || f.hidden === true || hasRuled(payload, f.type === 'blocks' ? variants(payload, f).flatMap((b) => b.fields) : f.fields, depth + 1))
}
/** True when writing `v` to field `f` would touch a ruled or hidden field. Lists are rewritten whole, so one holding any is refused. */
function touches(payload: Payload, v: unknown, f: Field, depth = 0): boolean {
  if (ruled(f) || f.hidden === true || depth > 60) return true
  if (f.type === 'array' || f.type === 'blocks') return hasRuled(payload, f.type === 'blocks' ? variants(payload, f).flatMap((b) => b.fields) : f.fields)
  if (f.type === 'group' && v && typeof v === 'object') return level(f.fields).some((c) => c.name! in (v as Doc) && touches(payload, (v as Doc)[c.name!], c, depth + 1))
  return false
}
const fieldsOf = (payload: Payload, slug: string, global: boolean) =>
  ((global ? payload.config.globals.find((g) => g.slug === slug) : payload.config.collections.find((c) => c.slug === slug)) as { fields?: Field[] } | undefined)?.fields

/** Strings that are structure, not words: they never change. */
const STRUCTURE = new Set(['id', '_id', 'relationTo', 'blockType', 'type', 'version', 'collection', 'globalType'])
/**
 * True when `next` differs from `now` only in text: the same keys and list lengths, the same numbers, booleans,
 * relationships and block types; only strings may change.
 */
function onlyText(now: unknown, next: unknown, key = '', depth = 0): boolean {
  if (depth > 60) return false
  if (typeof now === 'string' && typeof next === 'string') return now === next || !STRUCTURE.has(key)
  if (Array.isArray(now) && Array.isArray(next)) return now.length === next.length && now.every((x, i) => onlyText(x, next[i], key, depth + 1))
  if (now && next && typeof now === 'object' && typeof next === 'object') {
    const a = Object.keys(now), b = Object.keys(next)
    return a.length === b.length && a.every((k) => k in next && onlyText((now as Doc)[k], (next as Doc)[k], k, depth + 1))
  }
  return now === next
}

/** A relationship value (an id, or `{ relationTo, value }` for several collections) as the collection and id it points at. */
type Rel = { collection: string; id: string }
function relOne(v: unknown, f: Field): Rel | null {
  const to = Array.isArray(f.relationTo) ? f.relationTo : f.relationTo ? [f.relationTo] : []
  if (v && typeof v === 'object') {
    const o = v as Doc
    return typeof o.relationTo === 'string' && to.includes(o.relationTo) && (typeof o.value === 'string' || typeof o.value === 'number') ? { collection: o.relationTo, id: String(o.value) } : null
  }
  return (typeof v === 'string' || typeof v === 'number') && to.length === 1 ? { collection: to[0]!, id: String(v) } : null
}
type Ctx = { payload: Payload; rels: Rel[] }
const isRow = (x: unknown): x is Doc => Boolean(x) && typeof x === 'object' && !Array.isArray(x)
/** The fields of a row or group: the same keys, each changed only the way its kind allows. */
function sameFields(ctx: Ctx, fields: Field[] | undefined, now: unknown, next: unknown, depth: number): boolean {
  if (!isRow(now) || !isRow(next)) return false
  const known = level(fields)
  const a = Object.keys(now).filter((k) => k !== 'id'), b = Object.keys(next).filter((k) => k !== 'id')
  if (a.length !== b.length || !a.every((k) => k in next)) return false
  return a.every((k) => (k === 'blockType' || k === 'blockName' ? now[k] === next[k] : compat(ctx, known.find((x) => x.name === k), now[k], next[k], k, depth + 1)))
}
/**
 * True when `next` is what `now` may become. Text may change (never structure keys); numbers, yes/no and dates stay what
 * they are; a list's rows may be reordered, removed or copied (a row that was never there is refused: a copy must be
 * shaped like one that is, with no id of its own); a relationship or upload may point at another document of the
 * collections it allows (checked to exist before anything is written). Nothing else changes.
 */
function compat(ctx: Ctx, f: Field | undefined, now: unknown, next: unknown, key = '', depth = 0): boolean {
  if (depth > 60) return false
  // What isn't changing is always fine (an empty list, a number nobody filled in).
  if (JSON.stringify(now) === JSON.stringify(next)) return true
  const t = f?.type
  if (t === 'relationship' || t === 'upload') {
    const many = Boolean(f!.hasMany) || Array.isArray(now) || Array.isArray(next)
    if (!many) {
      if (JSON.stringify(now) === JSON.stringify(next)) return true
      const r = relOne(next, f!)
      const nv = next && typeof next === 'object' ? (next as Doc).value : next
      if (!r || (now !== null && now !== undefined && typeof now !== 'object' && typeof now !== typeof nv)) return false
      ctx.rels.push(r)
      return true
    }
    if (!Array.isArray(next) || next.length === 0) return false
    const was = new Set((Array.isArray(now) ? now : []).map((x) => relOne(x, f!)).filter((r): r is Rel => Boolean(r)).map((r) => r.collection + '.' + r.id))
    for (const x of next) {
      const r = relOne(x, f!)
      if (!r) return false
      if (!was.has(r.collection + '.' + r.id)) ctx.rels.push(r)
    }
    return true
  }
  if (t === 'array' || t === 'blocks') {
    if (!Array.isArray(now) || !Array.isArray(next) || next.length === 0 || next.length > 200) return false
    const byId = new Map(now.filter(isRow).map((r) => [String(r.id), r]))
    return next.every((item) => {
      if (!isRow(item)) return false
      const make = (row: Doc) => sameFields(ctx, inner(ctx.payload, f!, row), row, item, depth)
      if (item.id !== undefined) {
        const row = byId.get(String(item.id))
        return Boolean(row) && make(row!)
      }
      // A copy: shaped like some row that is there, with no id of its own.
      for (const row of now) {
        const mark = ctx.rels.length
        if (isRow(row) && make(row)) return true
        ctx.rels.length = mark
      }
      return false
    })
  }
  if (t === 'group') return sameFields(ctx, f!.fields, now, next, depth)
  // A field the config says is a choice or plain text may change to what it allows, whatever it is called (a select named "type").
  if ((t === 'select' || t === 'radio') && !f!.hasMany) {
    const allowed = (f!.options ?? []).map((o) => (typeof o === 'string' ? o : o?.value))
    return typeof next === 'string' && allowed.includes(next) && (now === null || now === undefined || typeof now === 'string')
  }
  if ((t === 'text' || t === 'textarea') && !f!.hasMany) return typeof next === 'string' && (now === null || now === undefined || typeof now === 'string')
  if (t === 'number') return typeof next === 'number' && Number.isFinite(next) && (now === null || now === undefined || typeof now === 'number')
  if (t === 'checkbox') return typeof next === 'boolean' && (now === null || now === undefined || typeof now === 'boolean')
  if (t === 'date') return typeof next === 'string' && !Number.isNaN(Date.parse(next)) && (now === null || now === undefined || typeof now === 'string')
  return onlyText(now, next, key, depth)
}
/** The same document without what Payload makes for itself: a copy of it has no ids and no dates. */
function stripDoc(v: unknown, top = true, depth = 0): unknown {
  if (depth > 60 || !v || typeof v !== 'object') return v
  if (Array.isArray(v)) return v.map((x) => stripDoc(x, false, depth + 1))
  const out: Doc = {}
  for (const [k, x] of Object.entries(v as Doc)) {
    if (k === 'id' || (top && (k === 'createdAt' || k === 'updatedAt' || k === '_status' || k === 'globalType'))) continue
    out[k] = stripDoc(x, false, depth + 1)
  }
  return out
}
/** Documents the new relations point at must be there, in a collection Tova may change. */
async function relsExist(payload: Payload, rels: Rel[], allow: Allow): Promise<boolean> {
  for (const r of rels) {
    if (!isWords(payload, r.collection, allow)) return false
    const doc = await payload.findByID({ collection: r.collection as CollectionSlug, id: r.id, depth: 0, overrideAccess: true, disableErrors: true }).catch(() => null)
    if (!doc) return false
  }
  return true
}

/** A fingerprint of a document as read, so a write can tell if anyone saved it in between. */
const fingerprint = async (doc: Doc) => hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(doc))))

/**
 * Published documents and globals, a page at a time. `words`: as the REST API shows them (Payload's read hooks run),
 * for Tova's editor. `export`: as stored (the database adapter's own read, no hooks), for loading into the throwaway
 * database Tova builds its copy of the site from, so ids, relationships and lists come back exactly.
 */
async function read(payload: Payload, input: { cursor?: string; mode?: string }, allow: Allow) {
  const mode = input.mode === 'export' ? 'export' : 'words'
  const list = collections(payload, mode, allow)
  const [i = 0, page = 1] = String(input.cursor ?? '0.1').split('.').map(Number)
  const locale = mode === 'export' && payload.config.localization ? { locale: 'all' as const } : {}
  const out: { collection: string; doc: Doc }[] = []
  if (i === 0 && page === 1)
    for (const g of payload.config.globals) {
      if (!globalAllowed(g.slug, mode, allow)) continue
      const doc = asDoc(
        mode === 'export'
          ? await payload.db.findGlobal({ slug: g.slug, ...locale })
          : await payload.findGlobal({ slug: g.slug as GlobalSlug, depth: 0, draft: false, overrideAccess: true }),
      )
      if (doc && Object.keys(doc).length) out.push({ collection: 'global', doc: { ...scrub(payload, doc, fieldsOf(payload, g.slug, true), mode === 'words', mode === 'export' && Boolean(payload.config.localization)), globalType: g.slug } })
    }
  const c = list[i]
  if (!c) return { docs: out, next: null, adapter: payload.db.name }
  // Published only: a document that was never published stays out.
  const where = c.versions?.drafts ? { where: { _status: { not_equals: 'draft' } } as never } : {}
  const r =
    mode === 'export'
      ? await payload.db.find({ collection: c.slug, limit: PAGE, page, pagination: true, sort: 'id', ...where, ...locale })
      : await payload.find({ collection: c.slug as CollectionSlug, depth: 0, draft: false, overrideAccess: true, limit: PAGE, page, ...where })
  for (const d of r.docs.map(asDoc)) out.push({ collection: c.slug, doc: scrub(payload, safe(d, Boolean(c.auth)), c.fields as Field[], mode === 'words', mode === 'export' && Boolean(payload.config.localization)) })
  const next = r.hasNextPage ? `${i}.${page + 1}` : list[i + 1] ? `${i + 1}.1` : null
  return { docs: out, next, adapter: payload.db.name }
}

async function get(payload: Payload, collection: string, id: string, allow: Allow) {
  if (collection === 'global') {
    if (!payload.config.globals.some((g) => g.slug === id) || !globalAllowed(id, 'words', allow)) return null
    const [doc, newest] = await Promise.all([false, true].map((draft) => payload.findGlobal({ slug: id as GlobalSlug, depth: 0, draft, overrideAccess: true })))
    const fields = fieldsOf(payload, id, true)
    const [d, n] = [doc, newest].map((x) => scrub(payload, asDoc(x), fields, true, false))
    return { doc: d!, newest: n!, version: await fingerprint(d!) }
  }
  if (!isWords(payload, collection, allow)) return null
  const [doc, newest] = await Promise.all([false, true].map((draft) => payload.findByID({ collection: collection as CollectionSlug, id, depth: 0, draft, overrideAccess: true, disableErrors: true })))
  if (!doc) return null
  const fields = fieldsOf(payload, collection, false)
  const [d, n] = [doc, newest ?? doc].map((x) => scrub(payload, asDoc(x), fields, true, false))
  return { doc: d!, newest: n!, version: await fingerprint(d!) }
}

async function write(req: PayloadRequest, input: { collection?: string; id?: string; expect?: string; data?: Doc }, allow: Allow) {
  const { payload } = req
  const { collection = '', id = '', expect, data } = input
  if (!data || typeof data !== 'object' || !Object.keys(data).length) return reply({ error: 'nothing to write' }, 400)
  const now = await get(payload, collection, id, allow)
  if (!now) return reply({ error: 'not found' }, 404)
  const global = collection === 'global'
  const drafts = hasDrafts(payload, global ? id : collection, global)
  // Someone's unpublished draft would go live with this change: leave the document alone.
  if (drafts && now.newest._status === 'draft' && now.newest.updatedAt !== now.doc.updatedAt) return reply({ error: 'draft' }, 409)
  if (expect !== now.version) return reply({ error: 'changed' }, 409)
  const fields = level(fieldsOf(payload, global ? id : collection, global))
  for (const [k, v] of Object.entries(data)) {
    const f = fields.find((x) => x.name === k)
    if (f && touches(payload, v, f)) return reply({ error: `only text can change (${k})` }, 422)
  }
  const ctx: Ctx = { payload, rels: [] }
  for (const [k, v] of Object.entries(data)) if (FIXED.has(k) || AUTH_FIELD.test(k) || !(k in now.doc) || !compat(ctx, fields.find((x) => x.name === k), now.doc[k], v, k)) return reply({ error: `only text can change (${k})` }, 422)
  if (!(await relsExist(payload, ctx.rels, allow))) return reply({ error: 'only documents Tova may change can be linked' }, 422)
  const save = drafts ? { ...data, _status: 'published' } : data
  const context = { tova: true }
  try {
    const done = asDoc(
      global
        ? await payload.updateGlobal({ slug: id as GlobalSlug, data: save as never, depth: 0, draft: false, overrideAccess: true, req, context })
        : await payload.update({ collection: collection as CollectionSlug, id, data: save as never, depth: 0, draft: false, overrideAccess: true, req, context }),
    )
    return reply({ ok: true, updatedAt: done.updatedAt ?? null })
  } catch (e) {
    return invalid(e)
  }
}

/** Payload refused a save (a required field, a taken address, a value its select doesn't allow): Tova says so, in Payload's words. */
function invalid(e: unknown) {
  // Only Payload's own refusals (it names the fields) are the client's to fix; anything else is a fault and stays one.
  if (!((e as { data?: { errors?: unknown } })?.data?.errors) && (e as { name?: string })?.name !== 'ValidationError') throw e
  const errors = ((e as { data?: { errors?: { path?: string; message?: string }[] } }).data?.errors ?? []).slice(0, 3)
  const detail = errors.map((x) => `${x.path ?? ''} ${x.message ?? ''}`.trim()).join('; ') || (e instanceof Error ? e.message : '')
  return reply({ error: 'invalid', detail: detail.slice(0, 240) }, 422)
}

/** A new document, made as a copy of one that is there: the same fields, nothing new (see compat()). */
async function create(req: PayloadRequest, input: { collection?: string; from?: string; data?: Doc }, allow: Allow) {
  const { payload } = req
  const { collection = '', from = '', data } = input
  const cfg = payload.config.collections.find((c) => c.slug === collection)
  if (!cfg || cfg.auth || cfg.upload || !isWords(payload, collection, allow)) return reply({ error: 'not found' }, 404)
  if (!data || typeof data !== 'object' || Array.isArray(data)) return reply({ error: 'nothing to write' }, 400)
  const src = await get(payload, collection, from, allow)
  if (!src) return reply({ error: 'not found' }, 404)
  const base = stripDoc(src.doc) as Doc
  const fields = level(fieldsOf(payload, collection, false))
  const ctx: Ctx = { payload, rels: [] }
  for (const [k, v] of Object.entries(data)) {
    // Keys may be left out (search fields are), never added.
    if (FIXED.has(k) || AUTH_FIELD.test(k) || !(k in base)) return reply({ error: `a copy can only have the fields of the original (${k})` }, 422)
    const f = fields.find((x) => x.name === k)
    if (f && touches(payload, v, f)) return reply({ error: `only text can change (${k})` }, 422)
    if (!compat(ctx, f, base[k], v, k)) return reply({ error: `a copy can only change words (${k})` }, 422)
  }
  if (!(await relsExist(payload, ctx.rels, allow))) return reply({ error: 'only documents Tova may change can be linked' }, 422)
  const drafts = hasDrafts(payload, collection)
  const make = async (d: Doc) => asDoc(await payload.create({ collection: collection as CollectionSlug, data: (drafts ? { ...d, _status: 'published' } : d) as never, depth: 0, draft: false, overrideAccess: true, req, context: { tova: true } }))
  try {
    let made: Doc
    let later: Doc = {}
    try {
      made = await make(data)
    } catch (e) {
      // Some relationship fields filter by the document's own id (related posts, "not this one"), which a new document hasn't got yet:
      // they're set in a second save, once it has. Any other refusal stays one.
      const failed = ((e as { data?: { errors?: { path?: string }[] } }).data?.errors ?? []).map((x) => String(x.path ?? '').split('.')[0]!)
      const defer = failed.filter((k) => k in data && ['relationship', 'upload'].includes(String(fields.find((x) => x.name === k)?.type)))
      if (!failed.length || defer.length !== failed.length) throw e
      later = Object.fromEntries(defer.map((k) => [k, data[k]]))
      made = await make(Object.fromEntries(Object.entries(data).filter(([k]) => !defer.includes(k))))
    }
    if (Object.keys(later).length) {
      try {
        await payload.update({ collection: collection as CollectionSlug, id: String(made.id), data: (drafts ? { ...later, _status: 'published' } : later) as never, depth: 0, draft: false, overrideAccess: true, req, context: { tova: true } })
      } catch (e) {
        await payload.delete({ collection: collection as CollectionSlug, id: String(made.id), depth: 0, overrideAccess: true, req, context: { tova: true } }).catch(() => {})
        throw e
      }
    }
    const got = await get(payload, collection, String(made.id), allow)
    return reply({ ok: true, id: String(made.id), slug: typeof made.slug === 'string' ? made.slug : null, version: got?.version ?? null })
  } catch (e) {
    return invalid(e)
  }
}

/**
 * Unpublish (collections with drafts: it stays as a draft in Payload), publish it again (undo), or delete a document.
 * Only when the document is exactly as Tova last saw it (`expect`), so nobody's changes are lost. A delete is the one
 * thing here that can't be undone, so it has its own rule (version 5): a hidden document in a collection the owner
 * marked "Can be deleted", or a copy Tova made a few minutes ago and names in the request. Nothing else.
 */
async function docOp(req: PayloadRequest, input: { collection?: string; id?: string; action?: string; expect?: string; made?: unknown }, allow: Allow) {
  const { payload } = req
  const { collection = '', id = '', action, expect } = input
  const made = Array.isArray(input.made) ? input.made.filter((x): x is string => typeof x === 'string' && x.length <= 80).slice(0, 50) : []
  const cfg = payload.config.collections.find((c) => c.slug === collection)
  if (!cfg || cfg.auth || !isWords(payload, collection, allow) || !['unpublish', 'publish', 'delete'].includes(String(action))) return reply({ error: 'not found' }, 404)
  const now = await get(payload, collection, id, allow)
  if (!now) return reply({ error: 'not found' }, 404)
  if (expect !== now.version) return reply({ error: 'changed' }, 409)
  const context = { tova: true }
  try {
    if (action === 'delete') {
      // (a) a hidden document in a collection the owner marked "Can be deleted", or (b) a copy Tova made in this publish.
      const created = Date.parse(String(now.doc.createdAt ?? ''))
      const mine = made.includes(id) && Number.isFinite(created) && Date.now() - created <= MADE_WINDOW_MS
      const hidden = allow.del.has(collection) && hasDrafts(payload, collection) && now.doc._status === 'draft'
      if (!mine && !hidden) return reply({ error: 'not allowed' }, 403)
      await payload.delete({ collection: collection as CollectionSlug, id, depth: 0, overrideAccess: true, req, context })
      return reply({ ok: true })
    }
    if (!hasDrafts(payload, collection)) return reply({ error: 'no drafts' }, 409)
    if (now.newest._status === 'draft' && now.newest.updatedAt !== now.doc.updatedAt) return reply({ error: 'draft' }, 409)
    await payload.update({ collection: collection as CollectionSlug, id, data: { _status: action === 'unpublish' ? 'draft' : 'published' } as never, depth: 0, draft: false, overrideAccess: true, req, context })
    const after = await get(payload, collection, id, allow)
    return reply({ ok: true, version: after?.version ?? null })
  } catch (e) {
    return invalid(e)
  }
}

/** A new photo, into the upload collection a photo field points at. */
async function upload(req: PayloadRequest, input: { collection?: string; name?: string; type?: string; data?: string; alt?: string }, allow: Allow) {
  const { payload } = req
  const { collection = '', name = 'photo', type = '', data = '', alt } = input
  const cfg = payload.config.collections.find((c) => c.slug === collection)
  if (!cfg?.upload || cfg.auth || !isWords(payload, collection, allow)) return reply({ error: 'not found' }, 404)
  if (!IMAGE_TYPES.has(type) || typeof data !== 'string' || !data || data.length > MAX_UPLOAD) return reply({ error: 'not a photo Tova can add' }, 422)
  const buffer = Buffer.from(data, 'base64')
  try {
    const made = asDoc(
      await payload.create({
        collection: collection as CollectionSlug,
        data: (typeof alt === 'string' && alt ? { alt: alt.slice(0, 500) } : {}) as never,
        file: { data: buffer, mimetype: type, name: String(name).replace(/[^A-Za-z0-9._-]/g, '-').slice(0, 80) || 'photo', size: buffer.length },
        depth: 0,
        overrideAccess: true,
        req,
        context: { tova: true },
      }),
    )
    return reply({ ok: true, id: String(made.id), filename: typeof made.filename === 'string' ? made.filename : null, sizes: made.sizes ?? null })
  } catch (e) {
    return invalid(e)
  }
}

/** The page addresses a collection already has (published or draft), so a new page takes a free one. */
async function slugs(payload: Payload, input: { collection?: string }, allow: Allow) {
  const collection = String(input.collection ?? '')
  if (!isWords(payload, collection, allow)) return null
  const r = await payload.find({ collection: collection as CollectionSlug, depth: 0, limit: 2000, pagination: false, draft: hasDrafts(payload, collection), overrideAccess: true, select: { slug: true } as never }).catch(() => null)
  return { slugs: (r?.docs ?? []).map(asDoc).map((d) => d.slug).filter((x): x is string => typeof x === 'string') }
}

/** What kind each field is, by path (`layout[].links[].label`): names and kinds, never values. */
type Hint = { t: string; many?: boolean; to?: string[]; o?: string[] }
function hintsFor(payload: Payload, fields: Field[] | undefined, prefix: string, out: Record<string, Hint>, depth = 0) {
  if (depth > 12) return
  for (const f of level(fields)) {
    if (ruled(f) || f.hidden === true || Object.keys(out).length > 4000) continue
    const path = prefix ? `${prefix}.${f.name}` : (f.name as string)
    const h: Hint = { t: f.type ?? 'text' }
    if (f.hasMany) h.many = true
    if (f.relationTo) h.to = ([] as string[]).concat(f.relationTo)
    if (f.options) h.o = f.options.map((o) => (typeof o === 'string' ? o : o?.value)).filter((o): o is string => typeof o === 'string').slice(0, 100)
    out[path] = h
    if (f.type === 'group') hintsFor(payload, f.fields, path, out, depth + 1)
    if (f.type === 'array') hintsFor(payload, f.fields, `${path}[]`, out, depth + 1)
    if (f.type === 'blocks') for (const b of variants(payload, f)) hintsFor(payload, b.fields, `${path}[]`, out, depth + 1)
  }
}
function schema(payload: Payload, allow: Allow) {
  const out: Record<string, { drafts?: true; upload?: true; hints: Record<string, Hint> }> = {}
  for (const c of collections(payload, 'words', allow)) {
    const hints: Record<string, Hint> = {}
    hintsFor(payload, c.fields as Field[], '', hints)
    out[c.slug] = { ...(c.versions?.drafts ? { drafts: true as const } : {}), ...(c.upload ? { upload: true as const } : {}), hints }
  }
  for (const g of payload.config.globals) {
    if (!globalAllowed(g.slug, 'words', allow)) continue
    const hints: Record<string, Hint> = {}
    hintsFor(payload, g.fields as Field[], '', hints)
    out[`global:${g.slug}`] = { ...(g.versions?.drafts ? { drafts: true as const } : {}), hints }
  }
  return { schema: out }
}

async function hello(payload: Payload) {
  let version = 'unknown'
  try {
    const { readFileSync, existsSync } = await import('node:fs')
    const { join, dirname } = await import('node:path')
    // The installed Payload's package.json, from the app's folder up (monorepos keep it higher up).
    for (let dir = process.cwd(), n = 0; n < 5; dir = dirname(dir), n++) {
      const file = join(dir, 'node_modules', 'payload', 'package.json')
      if (existsSync(file)) {
        version = JSON.parse(readFileSync(file, 'utf8')).version
        break
      }
    }
  } catch {
    version = 'unknown'
  }
  return {
    ok: true,
    plugin: PLUGIN_VERSION,
    site: SITE,
    keys: KEYS.map((k) => k.slice(0, 8)),
    payload: version,
    adapter: payload.db.name,
    package: (payload.db as { packageName?: string }).packageName ?? null,
    words: payload.config.collections.filter((c) => !shut(c.slug) && !c.auth && !NOT_WORDS.test(c.slug)).map((c) => c.slug),
    globals: payload.config.globals.filter((g) => !EXCLUDE.includes(g.slug)).map((g) => g.slug),
    uploads: payload.config.collections.filter((c) => c.upload && !shut(c.slug)).map((c) => c.slug),
    // Names only, so the owner can choose in Tova: what each collection is, never what's in it.
    collections: payload.config.collections
      .filter((c) => !shut(c.slug))
      .map((c) => ({ slug: c.slug, auth: Boolean(c.auth), upload: Boolean(c.upload), label: label(c.labels?.plural) })),
    globalLabels: Object.fromEntries(payload.config.globals.filter((g) => !EXCLUDE.includes(g.slug) && label(g.label)).map((g) => [g.slug, label(g.label)])),
  }
}
const label = (l: unknown) => (typeof l === 'string' && l.length <= 60 ? l : undefined)

/** How a phrase is compared (Tova normalizes the same way). */
const norm = (s: string) => s.replace(/\s+/g, ' ').trim().toLowerCase()
/** Only words long enough to mean something count as shown (not a lone "Paid" or "Active"). */
const counts = (s: string) => s.length >= 16 || (s.length >= 8 && s.includes(' '))
function anyString(v: unknown, hit: (s: string) => boolean, depth = 0): boolean {
  if (depth > 40 || v === null || v === undefined) return false
  if (typeof v === 'string') return hit(v)
  if (Array.isArray(v)) return v.some((x) => anyString(x, hit, depth + 1))
  if (typeof v === 'object') return Object.values(v).some((x) => anyString(x, hit, depth + 1))
  return false
}
/**
 * For Tova's defaults: per collection (and global), how many published documents have words that appear on the live
 * site's pages, whose phrases Tova sends (they're public already). Only the counts leave the site.
 */
async function survey(payload: Payload, input: Doc) {
  const phrases = new Set((Array.isArray(input.phrases) ? input.phrases : []).slice(0, 3000).filter((p): p is string => typeof p === 'string').map(norm))
  // shown: words long enough to mean something (decides what editors get by default). seen: any match, even one word
  // like a category's name (decides whether Tova's copy of the site needs a collection that's switched off).
  const on = (s: string) => phrases.has(norm(s).slice(0, 120))
  const hit = (s: string) => counts(norm(s)) && on(s)
  const out: Record<string, { docs: number; shown: number; seen: number }> = {}
  for (const c of payload.config.collections) {
    if (shut(c.slug) || c.auth) continue
    const where = c.versions?.drafts ? { where: { _status: { not_equals: 'draft' } } as never } : {}
    const r = await payload.db.find({ collection: c.slug, limit: SURVEY_DOCS, page: 1, pagination: true, ...where }).catch(() => null)
    if (!r) continue
    const docs = r.docs.map(asDoc).map((d) => scrub(payload, d, c.fields as Field[], false, false))
    out[c.slug] = { docs: Number((r as { totalDocs?: number }).totalDocs ?? docs.length), shown: docs.filter((d) => anyString(d, hit)).length, seen: docs.filter((d) => anyString(d, on)).length }
  }
  for (const g of payload.config.globals) {
    if (EXCLUDE.includes(g.slug)) continue
    const d = asDoc(await payload.db.findGlobal({ slug: g.slug }).catch(() => null))
    const doc = d && Object.keys(d).length ? scrub(payload, d, fieldsOf(payload, g.slug, true), false, false) : null
    out[`global:${g.slug}`] = { docs: doc ? 1 : 0, shown: doc && anyString(doc, hit) ? 1 : 0, seen: doc && anyString(doc, on) ? 1 : 0 }
  }
  return { counts: out }
}

/**
 * The request's body, read no further than MAX_BODY: a bigger one is refused part way, whether or not it said its
 * size. Null when it's too big.
 */
async function bodyOf(req: PayloadRequest, max = MAX_BODY): Promise<string | null> {
  const stream = (req as { body?: ReadableStream<Uint8Array> | null }).body
  if (stream && typeof stream.getReader === 'function') {
    const reader = stream.getReader()
    const parts: Uint8Array[] = []
    let size = 0
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.byteLength
      if (size > max) {
        await reader.cancel().catch(() => {})
        return null
      }
      parts.push(value)
    }
    const all = new Uint8Array(size)
    let at = 0
    for (const p of parts) all.set(p, (at += p.byteLength) - p.byteLength)
    return new TextDecoder().decode(all)
  }
  const text = req.text ? await req.text() : ''
  return text.length > max ? null : text
}

/** Add to your Payload config's plugins: `plugins: [tova()]`. */
export const tova =
  () =>
  (config: Config): Config => ({
    ...config,
    endpoints: [
      ...(config.endpoints ?? []),
      {
        path: '/tova/:op',
        method: 'post',
        handler: async (req) => {
          const op = String((req as { routeParams?: Record<string, unknown> }).routeParams?.op ?? '')
          // Refused before reading, when the request says it's too big (anyone can send one; only Tova's are signed).
          const max = op === 'upload' ? MAX_UPLOAD : MAX_BODY
          if (Number(req.headers.get('content-length') ?? 0) > max) return reply({ error: 'too large' }, 413)
          const body = await bodyOf(req, max)
          if (body === null) return reply({ error: 'too large' }, 413)
          const refused = await signedBy(req, op, body)
          if (refused) return reply({ error: refused }, 401)
          let input: Doc = {}
          try {
            input = body ? JSON.parse(body) : {}
          } catch {
            return reply({ error: 'bad body' }, 400)
          }
          if (op === 'hello') return reply(await hello(req.payload))
          if (op === 'survey') return reply(await survey(req.payload, input))
          // Everything else answers only for the collections the site's owner chose in Tova.
          const allow = allowOf(input)
          if (!allow && ['read', 'get', 'write', 'schema', 'create', 'doc', 'upload', 'slugs'].includes(op)) return reply({ error: 'no allow-list' }, 400)
          if (op === 'read') return reply(await read(req.payload, input, allow!))
          if (op === 'get') {
            const found = await get(req.payload, String(input.collection), String(input.id), allow!)
            return found ? reply(found) : reply({ error: 'not found' }, 404)
          }
          if (op === 'write') return write(req, input, allow!)
          if (op === 'schema') return reply(schema(req.payload, allow!))
          if (op === 'create') return create(req, input, allow!)
          if (op === 'doc') return docOp(req, input, allow!)
          if (op === 'upload') return upload(req, input, allow!)
          if (op === 'slugs') {
            const found = await slugs(req.payload, input, allow!)
            return found ? reply(found) : reply({ error: 'not found' }, 404)
          }
          return reply({ error: 'unknown' }, 404)
        },
      },
    ],
  })
