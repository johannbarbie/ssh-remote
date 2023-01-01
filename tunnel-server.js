const net = require('net');
const { pubToAddr } = require('./utils');
const { utils: { parseKey }, Server } = require('ssh2');

module.exports = {
  start: (ip, port, hostKeys, servers) => {

    new Server({
      hostKeys,
      port
    }, (connection) => {
      console.log('Client connected!');

      connection.on('authentication', (ctx) => {
        let allowed = true;
        if (!servers[ctx.username]) {
          allowed = false;
          console.log('unknown user');
        }

        let addr;
        if (ctx.key && ctx.key.data){
          addr = pubToAddr(ctx.key.data);
        }
        switch (ctx.method) {
          case 'publickey':
            if (!ctx.key || ctx.key.data.length < 32 || !servers[addr]) {
              return ctx.reject();
            }
            console.log(addr, servers[addr]);
            let allowedPubKey = parseKey(servers[addr].pub);
            if (ctx.key.algo !== allowedPubKey.type
                || ctx.key.data.compare(allowedPubKey.getPublicSSH()) !== 0
                || (ctx.signature && allowedPubKey.verify(ctx.blob, ctx.signature) !== true)) {
              console.log(`invalid authentication for ${addr}`);
              return ctx.reject();
            }
            break;
          default:
            return ctx.reject();
        }

        if (allowed) {
          connection.addr = addr;
          ctx.accept();
        } else
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

              if (servers[connection.addr].port) {
                console.log(`${connection.addr} trying to bind multiple ports, existing port ${servers[connection.addr].port}`);
                return reject();
              }
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
              server.listen(0, () => {
                console.log(`${connection.addr} bound to port ${server.address().port}`);
                servers[connection.addr].port = server.address().port;
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
          delete servers[connection.addr].port;
        };
        console.log('Client disconnected');
      });
    }).listen(port, ip, function() {
      console.log(`Tunnel Server listening on ${ip}:${port}`);
    });
  }
}