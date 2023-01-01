const { readFileSync } = require('fs');
const restApi = require('./rest-api');
const tunnelServer = require('./tunnel-server');

let servers = {};

restApi.start(
  8081,
  servers);

tunnelServer.start(
  '0.0.0.0',
  1337,
  [readFileSync('etc/ssh/ssh_host_ed25519_key')],
  servers);
