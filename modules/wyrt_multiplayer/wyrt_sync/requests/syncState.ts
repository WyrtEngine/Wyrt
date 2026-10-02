import { Request } from '../../../../src/types/Request';
import { cleanState, update } from '../rooms';

const handler: Request = {
  cost: 0.1, // sent ~15 times a second
  auth: false,
  exec: async function (u, _data, payload) {
    const s = cleanState(payload.s);
    if (s) update(u.id, s);
  },
};

export default handler;
