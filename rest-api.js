const express = require('express');
const { pubToAddr } = require('./utils');

let instance;

module.exports = {

  start: (port, db) => {
    const app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    app.get('/servers', (req, res) => {
      return res.send(db);
    });

    app.get('/servers/:addr', (req, res) => {
      return res.send(db[req.params.addr]);
    });

    app.post('/servers', (req, res) => {
      const pub = Buffer.from(req.body.pubKeyBase64, 'base64');
      const addr = pubToAddr(pub);
      if (db[addr]) {
        return res.status(409).send('server key already registered');
      }
      db[addr] = {pub: `ssh-ed25519 ${req.body.pubKeyBase64}`};
      let rsp = {};
      rsp[addr] = db[addr];
      return res.send(rsp);
    });

    app.listen(port, '127.0.0.1', () =>
      console.log(`REST API listening on port ${port}!`),
    );
    return app;
  }
}
