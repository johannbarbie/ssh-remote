const { readFileSync } = require('fs');
const { inspect } = require('util');
const net = require('net');
const keccak256 = require('keccak256');
const base58check = require('base58check');

const { utils: { parseKey }, Server } = require('ssh2');

let accounts = {};

new Server({
  hostKeys: [readFileSync('etc/ssh/ssh_host_ed25519_key')],
  port: 1337
}, (connection) => {
  console.log('Client connected!');

  connection.on('authentication', (ctx) => {
    let allowed = true;
    if (!accounts[ctx.username]) {
      allowed = false;
    }

    switch (ctx.method) {
      case 'publickey':
        if (!ctx.key || ctx.key.data.length < 32) {
          return ctx.reject();
        }
        let addr = base58check.encode(keccak256(ctx.key.data).slice(12, 32));
        let allowedPubKey = parseKey(accounts[addr]);
        if (ctx.key.algo !== allowedPubKey.type
            || ctx.key.data.compare(allowedPubKey.getPublicSSH()) !== 0
            || (ctx.signature && allowedPubKey.verify(ctx.blob, ctx.signature) !== true)) {
          return ctx.reject();
        }
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
    connection
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
            connection.forwardOut(
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
          connection.server = server;
        } else {
          reject();
        }
      });
  }).on('close', () => {
    if (connection.server) {
      for (var i in connection.server.sockets) {
          connection.server.sockets[i].destroy();
      }
      connection.server.close(function () {
          console.log('server closed.');
          connection.server.unref();
      });
    };
    console.log('Client disconnected');
  });
}).listen(1337, '127.0.0.1', function() {
  console.log('Listening on port ' + this.address().port);
});