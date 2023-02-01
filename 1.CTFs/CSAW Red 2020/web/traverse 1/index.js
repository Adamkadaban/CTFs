const Koa = require('koa');
const logger = require('koa-logger');
const fs = require('fs');
const app = new Koa();


/**
   Read a file and return it as a string
 */
function readFile(filepath) {
  return fs.readFileSync(filepath, {encoding: 'utf8'});
}


app.use(logger());
app.use(async ctx => {
  // Get the filepath from the http get query
  // https://en.wikipedia.org/wiki/Query_string
  const filepath = ctx.query.filepath || 'index.html';

  // Return the file as a response
  ctx.body = readFile(filepath);
});

console.log('http://0.0.0.0:5000/')
app.listen(5000);
