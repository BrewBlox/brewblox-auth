import Minimist from 'minimist';

export default Minimist(process.env.ARGS?.split(' ') || process.argv.slice(2), {
  string: ['name'],
  boolean: ['debug', 'local'],
  default: {
    name: 'auth',
    publicPort: 5000,
    privatePort: 5001,
    debug: false,
    local: false,
  },
});
