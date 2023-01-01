const keccak256 = require('keccak256');
const base58check = require('base58check');


module.exports = {

  pubToAddr: (data, algo) => {
    let addr = base58check.encode(keccak256(data).slice(12, 32));
    return addr;
  }

}
