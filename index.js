const { timingSafeEqual } = require('crypto');
const { readFileSync } = require('fs');
const { inspect } = require('util');
const net = require('net');
const keccak256 = require('keccak256');
const base58check = require('base58check');

const { utils: { parseKey }, Server } = require('ssh2');

const allowedUser = Buffer.from('foo');
const allowedPubKey = parseKey(readFileSync('etc/foo/foo.pub'));

function checkValue(input, allowed) {
  const autoReject = (input.length !== allowed.length);
  if (autoReject) {
    // Prevent leaking length information by always making a comparison with the
    // same input when lengths don't match what we expect ...
    allowed = input;
  }
  const isMatch = timingSafeEqual(input, allowed);
  return (!autoReject && isMatch);
}

let clients = {};

new Server({
  hostKeys: [readFileSync('etc/ssh/ssh_host_ed25519_key')],
  port: 1337
}, (client) => {
  console.log('Client connected!');

  client.on('authentication', (ctx) => {
    let allowed = true;
    if (!checkValue(Buffer.from(ctx.username), allowedUser))
      allowed = false;

    switch (ctx.method) {
      case 'password':
        return ctx.reject();
        break;
      case 'publickey':
        if (ctx.key.algo !== allowedPubKey.type
            || !checkValue(ctx.key.data, allowedPubKey.getPublicSSH())
            || (ctx.signature && allowedPubKey.verify(ctx.blob, ctx.signature) !== true)) {
          return ctx.reject();
        }
        let addr = base58check.encode(keccak256(ctx.key.data).slice(12, 32));
        clients[addr] = client;
        break;
      default:
        return ctx.reject();
    }

    if (allowed)
      ctx.accept();
    else
      ctx.reject();
  }).on('ready', () => {

    console.log('Client authenticated!');
    client
      .on('session', (accept, reject) => {
        let session = accept();
        session.on('shell', function(accept, reject) {
          let stream = accept();
        });
      })
      .on('request', (accept, reject, name, info) => {
        if (name === 'tcpip-forward') {

          
          let server = net.createServer({}, (socket) => {
            socket.setEncoding('utf8');
            if (!server.sockets) {
              server.sockets = [];
            }
            server.sockets.push(socket);
            client.forwardOut(
              info.bindAddr, info.bindPort,
              socket.remoteAddress, socket.remotePort,
              (err, upstream) => {
                if (err) {
                  socket.end();
                  return console.error('not working: ' + err);
                }
                upstream.pipe(socket).pipe(upstream);
              });
          });
          server.on('error', (err) => {
            console.log(err.toString());
            reject();
          });
          server.listen(info.bindPort, () => {
            accept();
          });
          client.server = server;
        } else {
          reject();
        }
      });
  }).on('close', () => {
    if (client.server) {
      for (var i in client.server.sockets) {
          client.server.sockets[i].destroy();
      }
      client.server.close(function () {
          console.log('server closed.');
          client.server.unref();
      });
    };
    console.log('Client disconnected');
  });
}).listen(1337, '127.0.0.1', function() {
  console.log('Listening on port ' + this.address().port);
});