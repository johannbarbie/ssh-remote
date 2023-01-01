const { readFileSync } = require('fs');
const RestApi = require('./rest-api');
const TunnelServer = require('./tunnel-server');

let servers = {};

RestApi.start(8081, servers);

TunnelServer.start(
  '0.0.0.0',
  1337,
  [readFileSync('etc/ssh/ssh_host_ed25519_key')],
  servers);
