'use strict'

const express = require('express')
const path = require('path')
const logger = require('morgan')
const cookieParser = require('cookie-parser')
const bodyParser = require('body-parser')
const favicon = require('serve-favicon')

const routes = require('./routes/index')
const users = require('./routes/users')
const ipfilter = require('express-ipfilter').IpFilter
const IpDeniedError = require('express-ipfilter').IpDeniedError

const app = express()

// view engine setup
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'pug')

// uncomment after placing your favicon in /public
app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

const ips = ['::ffff:127.0.0.1']
app.use(ipfilter(ips, { mode: 'allow' }))

app.use('/', routes)
app.use('/users', users)

// catch 404 and forward to error handler
app.use((req, res, next) => {
  const err = new Error('Not Found')
  err.status = 404
  next(err)
})

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use((err, req, res) => {
    console.log('Error handler', err)
    if (err instanceof IpDeniedError) {
      res.status(401)
    } else {
      res.status(err.status || 500)
    }

    res.render('error', {
      message: 'You shall not pass',
      error: err
    })
  })
}

// production error handler
// no stacktraces leaked to user
app.use((err, req, res) => {
  console.log('Error handler', err)
  res.status(err.status || 500)
  res.render('error', {
    message: err.message,
    error: {}
  })
})

module.exports = app
