import { Request } from '../../../../src/types/Request';
import { cleanName, join } from '../rooms';

const handler: Request = {
  cost: 5,
  auth: false, // guests: a name is enough
  exec: async function (u, _data, payload) {
    const room = typeof payload.room === 'string' ? payload.room.slice(0, 64) : '';
    if (!room) return u.error('syncJoin needs a room');
    const err = join(u, room, cleanName(payload.name, u.id));
    if (err) u.error(err);
  },
};

export default handler;
