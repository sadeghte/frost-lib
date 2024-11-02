const addon = require('./build/Release/node_addon');

const test = addon.keys_generate_with_dealer(2, 3)

console.log(test);