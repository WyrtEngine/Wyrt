import { Request } from '../../../src/types/Request';
import { relay } from '../rooms';

const handler: Request = {
  cost: 0.3,
  auth: false,
  exec: async function (u, _data, payload) {
    if (typeof payload.n !== 'string' || payload.n.length > 32) return;
    const d = payload.d === undefined ? undefined : JSON.stringify(payload.d).length <= 512 ? payload.d : undefined;
    relay(u.id, { n: payload.n, d });
  },
};

export default handler;
