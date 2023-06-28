import Minimist from 'minimist';

export default Minimist(process.env.ARGS?.split(' ') || process.argv.slice(2), {
  string: ['name'],
  boolean: ['debug', 'local'],
  default: {
    name: 'auth',
    port: 5000,
    debug: false,
    local: false,
  },
});
