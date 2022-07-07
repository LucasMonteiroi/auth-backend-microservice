#!/bin/env node

const { spawn } = require('child_process');
const args = process.argv.slice(2);
const version = args[0];
let patch = '';

switch (version) {
  case 'patch':
    patch = 'bump:patch';
    break;
  case 'minor':
    patch = 'bump:minor';
    break;
  case 'major':
    patch = 'bump:major';
    break;
  default:
    patch = 'bump:patch';
    break;
}

console.log(patch);

spawn(
  'yarn',
  [
    patch,
    '&&',
    'yarn',
    'gitmoji-changelog',
    '&&',
    'git',
    'add',
    '.',
    '&&',
    'git',
    'commit',
    '-m',
    '":pencil:: update CHANGELOG.md"',
    '&&',
    'git',
    'push',
  ],
  {
    stdio: 'inherit',
    shell: true,
  },
);
