#!/usr/bin/env node
const Sentinet = require('../lib');
const path = require('path');
const argv = require('minimist')(process.argv.slice(2));

const iface = argv.iface || process.env.SENTINET_INTERFACE || null;
const python = argv.python || 'python';

const s = new Sentinet({ pythonPath: python, iface });

s.on('stdout', (d) => process.stdout.write(d));
s.on('stderr', (d) => process.stderr.write(d));
s.on('alert', (a) => console.log('ALERT:', JSON.stringify(a)));

s.start();

process.on('SIGINT', () => { s.stop(); process.exit(0); });
