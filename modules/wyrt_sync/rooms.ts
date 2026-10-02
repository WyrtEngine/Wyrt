/**
 * Rooms of players who see each other.
 *
 * The server doesn't know the game. Each client owns its own player (and
 * whatever it rides) and sends that state; the server keeps the latest copy,
 * checks it is sane, and sends everyone else's to each member 15 times a second.
 * Shared things a player moved (a horse, a boat) are remembered per room so
 * late joiners find them where they were left.
 */

import { User } from '../../src/types/User';

export const TICK_MS = 1000 / 15;
const MAX_PLAYERS = 24;
const MAX_ROOMS = 200;

/** One player's state as the client sent it (ground pixels, radians) */
export interface PlayerState {
  a: string;            // area
  x: number; y: number; // ground position
  z: number;            // height above the ground (jumps)
  f: number;            // facing
  vx: number; vy: number;
  hp?: number;
  t?: number;           // tint
  r?: { k: string; x: number; y: number; z: number; f: number; m: boolean } | null; // riding: shared object key and its state
}

export interface SharedObject { k: string; a: string; x: number; y: number; f: number }

interface Member { user: User; id: number; name: string; state: PlayerState | null; dirty: boolean }
interface Room { key: string; members: Map<number, Member>; objects: Map<string, SharedObject> }

const rooms = new Map<string, Room>();
const roomOf = new Map<number, Room>();

const num = (v: unknown, lim = 1e6): v is number => typeof v === 'number' && Number.isFinite(v) && Math.abs(v) <= lim;
const str = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= max;

export function cleanName(raw: unknown, id: number): string {
  const s = typeof raw === 'string' ? raw.replace(/[^\p{L}\p{N} _'-]/gu, '').trim().slice(0, 16) : '';
  return s || `Player ${id}`;
}

/** A state from the wire, or null when anything is off */
export function cleanState(raw: any): PlayerState | null {
  if (!raw || typeof raw !== 'object') return null;
  const { a, x, y, z, f, vx, vy, hp, t, r } = raw;
  if (!str(a, 32) || !num(x) || !num(y) || !num(z, 1e3) || !num(f, 100) || !num(vx, 1e4) || !num(vy, 1e4)) return null;
  const s: PlayerState = { a, x, y, z, f, vx, vy };
  if (num(hp, 1e6)) s.hp = hp;
  if (num(t, 0xffffff) && t >= 0) s.t = Math.floor(t);
  if (r && typeof r === 'object') {
    if (!str(r.k, 64) || !num(r.x) || !num(r.y) || !num(r.z, 1e3) || !num(r.f, 100)) return null;
    s.r = { k: r.k, x: r.x, y: r.y, z: r.z, f: r.f, m: !!r.m };
  }
  return s;
}

const send = (m: Member, msg: unknown) => { try { m.user.send(JSON.stringify(msg)); } catch { /* closed */ } };

export function join(user: User, roomKey: string, name: string): string | null {
  leave(user.id);
  let room = rooms.get(roomKey);
  if (!room) {
    if (rooms.size >= MAX_ROOMS) return 'Server is full';
    room = { key: roomKey, members: new Map(), objects: new Map() };
    rooms.set(roomKey, room);
  }
  if (room.members.size >= MAX_PLAYERS) return 'Room is full';
  const me: Member = { user, id: user.id, name, state: null, dirty: false };
  send(me, {
    type: 'sync:welcome', id: me.id, name,
    players: [...room.members.values()].map((m) => ({ id: m.id, name: m.name, s: m.state })),
    objects: [...room.objects.values()],
  });
  for (const m of room.members.values()) send(m, { type: 'sync:joined', id: me.id, name });
  room.members.set(me.id, me);
  roomOf.set(me.id, room);
  return null;
}

export function leave(id: number): void {
  const room = roomOf.get(id);
  if (!room) return;
  roomOf.delete(id);
  room.members.delete(id);
  for (const m of room.members.values()) send(m, { type: 'sync:left', id });
  if (room.members.size === 0) rooms.delete(room.key);
}

export function update(id: number, state: PlayerState): boolean {
  const room = roomOf.get(id);
  const me = room?.members.get(id);
  if (!room || !me) return false;
  // Whatever you ride is left where you were when you get off
  if (state.r) room.objects.set(state.r.k, { k: state.r.k, a: state.a, x: state.r.x, y: state.r.y, f: state.r.f });
  me.state = state;
  me.dirty = true;
  return true;
}

/** One-off things (an attack, a sound) go to everyone else in the room straight away */
export function relay(id: number, event: { n: string; d?: unknown }): boolean {
  const room = roomOf.get(id);
  if (!room) return false;
  for (const m of room.members.values()) if (m.id !== id) send(m, { type: 'sync:event', id, n: event.n, d: event.d });
  return true;
}

/** Each member gets everyone else's latest state */
export function tick(): void {
  for (const room of rooms.values()) {
    if (room.members.size < 2) { for (const m of room.members.values()) m.dirty = false; continue; }
    const changed = [...room.members.values()].filter((m) => m.dirty && m.state);
    if (changed.length === 0) continue;
    for (const m of room.members.values()) {
      const players = changed.filter((o) => o.id !== m.id).map((o) => ({ id: o.id, s: o.state }));
      if (players.length) send(m, { type: 'sync:snap', players });
    }
    for (const m of changed) m.dirty = false;
  }
}

export function stats(): { rooms: number; players: number } {
  return { rooms: rooms.size, players: roomOf.size };
}
