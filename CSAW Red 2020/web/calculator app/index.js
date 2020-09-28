const Koa = require('koa');
const logger = require('koa-logger');
const fs = require('fs');
const app = new Koa();

app.use(logger());

app.use(async (ctx, next) => {
  next()
    .catch(error => {
      ctx.status = 500;
      ctx.body = error.stack;
    });
})

app.use(async ctx => {
  const expression = ctx.query.expression;
  if (expression)
    ctx.body = (new String(eval(expression))).toString();
  else
    ctx.body = fs.readFileSync('index.html', {encoding: 'utf8'});
});

console.log('http://0.0.0.0:5000/')
app.listen(5000);
