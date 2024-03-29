const net = require('net');
const { pubToAddr } = require('./utils');
const { utils: { parseKey }, Server } = require('ssh2');

module.exports = {
  start: (ip, port, hostKeys, servers) => {

    new Server({
      hostKeys,
      port,
      banner: "heeeeeeeeeelllllllllllooooooooooooo!",
      greeting: "greeeeettting!!!!"
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
              stream.on('data', (data) => {
                console.log(`shell data: ${data}`);
              });
            });
            session.on('pty', function(accept, reject, info) {
              console.log(`pty: ${JSON.stringify(info)}`);
              //accept();
              reject();
            });
            session.on('exec', function(accept, reject, info) {
              console.log(`exec ${info}`);

              let stream = accept();
            });
          })
          .on('request', (accept, reject, name, info) => {
            if (name === 'tcpip-forward') {

              if (servers[connection.addr].port) {
                console.log(`${connection.addr} trying to bind multiple ports, existing port ${servers[connection.addr].port}`);
                return reject();
              }
              let server = net.createServer({allowHalfOpen: true}, (socket) => {

                socket.on('end', () => {
                  console.log('tunnel disconnected');
                });

                socket.on('error', function(e) {
                  console.log(e);
                });

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
                      console.error('not working: ' + err);
                      return;
                    }
                    upstream.pipe(socket).pipe(upstream);
                    upstream.on('error', (errUp) => {
                        console.error(`error up: ${errUp}`);
                    });
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
              console.log('destroying connections on server close...');
              connection.server.sockets[i].destroy();
          }
          connection.server.close(function () {
              console.log('server closed.');
              connection.server.unref();
          });
          delete servers[connection.addr].port;
        };
        console.log('Client disconnected');
      }).on('error', (err) => {
        if (connection.addr) {
          console.log(`client ${connection.addr} with error: ${err}`);
        }
        console.log(`client error: ${err}`);
      });
    }).listen(port, ip, function() {
      console.log(`Tunnel Server listening on ${ip}:${port}`);
    });
  }
}