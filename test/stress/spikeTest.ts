import { batch } from 'k6/http';
import { sleep } from 'k6';
import { Options } from 'k6/options';

export const options: Options = {
  stages: [
    { duration: '10s', target: 100 },
    { duration: '1m', target: 100 },
    { duration: '10s', target: 3000 },
    { duration: '1m', target: 3000 },
    { duration: '10s', target: 100 },
    { duration: '1m', target: 100 },
    { duration: '10s', target: 0 },
  ],
  dns: {
    ttl: '1m',
    select: 'first',
    policy: 'preferIPv6',
  },
};
export default function () {
  batch([['GET', `${__ENV.API_URL}/api/v1/tasks`]]);

  sleep(1);
}
