/**
 * WYRT SYNC - rooms of players who see each other
 *
 * Game-agnostic: clients send their own state and one-off events, the server
 * checks them and passes them on. Glyft's `network` rule speaks this protocol.
 *
 * Client to server (gameId not needed, the handlers are global):
 *   { type: 'syncJoin',  room, name }
 *   { type: 'syncState', s: { a, x, y, z, f, vx, vy, hp?, t?, r? } }   ~15 a second
 *   { type: 'syncEvent', n, d? }
 * Server to client:
 *   sync:welcome { id, name, players: [{ id, name, s }], objects: [{ k, a, x, y, f }] }
 *   sync:joined { id, name }   sync:left { id }
 *   sync:snap { players: [{ id, s }] }   sync:event { id, n, d }
 */

import { IModule, ModuleContext } from '../../src/module/IModule';
import { leave, stats, tick, TICK_MS } from './rooms';

export default class WyrtSyncModule implements IModule {
  name = 'wyrt_sync';
  version = '1.0.0';
  description = 'Room-based state sync for browser games';
  dependencies = ['wyrt_core'];

  private context?: ModuleContext;
  private timer?: ReturnType<typeof setInterval>;

  async initialize(context: ModuleContext): Promise<void> {
    this.context = context;
  }

  async activate(): Promise<void> {
    const ctx = this.context!;
    ctx.events.on('playerDisconnected', (u: { id: number }) => leave(u.id));
    this.timer = setInterval(tick, TICK_MS);
    ctx.logger.info('[wyrt_sync] Ready');
    // A tiny health check for monitoring
    (globalThis as any).httpServer?.get?.('/sync/health', (_req: unknown, res: { json(v: unknown): void }) => res.json({ ok: true, ...stats() }));
  }

  async deactivate(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
  }
}
