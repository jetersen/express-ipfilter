/*!
 * Express - IP Filter
 * Copyright(c) 2014 Bradley and Montgomery Inc.
 * MIT Licensed
 */

'use strict'

/**
 * Module dependencies.
 */
const _ = require('lodash')
const iputil = require('ip')
const rangeCheck = require('range_check')
const IpDeniedError = require('./deniedError')
const proxyaddr = require('proxy-addr')

/**
 * express-ipfilter:
 *
 * IP Filtering middleware;
 *
 * Examples:
 *
 *      const ipfilter = require('ipfilter'),
 *          ips = ['127.0.0.1'];
 *          getIps = function() { return ['127.0.0.1']; };
 *
 *      app.use(ipfilter(ips));
 *      app.use(ipfilter(getIps));
 *
 * Options:
 *
 *  - `mode` whether to deny or grant access to the IPs provided. Defaults to 'deny'.
 *  - `logF` Function to use for logging.
 *  - `log` console log actions. Defaults to true.
 *  - 'excluding' routes that should be excluded from ip filtering
 *  - 'trustProxy' trust proxy settings just like in express. The trust proxy setting is implemented using the proxy-addr package. (http://expressjs.com/en/guide/behind-proxies.html)
 *
 * @param [ips] {Array} IP addresses or {Function} that returns the array of IP addresses
 * @param [opts] {Object} options
 * @api public
 */
module.exports = function ipfilter(ips, opts) {
  ips = ips || false

  const getIps = _.isFunction(ips) ? ips : () => ips
  const logger = (message) => console.log(message)

  /**
   * Compile "proxy trust" value to function. (from express)
   *
   * @param  {Boolean|String|Number|Array|Function} val
   * @return {Function}
   * @api private
   */
  const compileTrust = (val) => {
    if (typeof val === 'function') return val

    if (val === true) {
      // Support plain true/falses
      return () => true
    }

    if (typeof val === 'number') {
      // Support trusting hop count
      return (a, i) => i < val
    }

    if (typeof val === 'string') {
      // Support comma-separated values
      val = val.split(',')
    }

    return proxyaddr.compile(val || [])
  }

  const settings = _.defaults(opts || {}, {
    mode: 'deny',
    log: true,
    logF: logger,
    excluding: [],
    trustProxy: false, // This is the default used by express.
  })

  if (!_.isFunction(settings.detectIp)) {
    settings.detectIp = (req) =>
      proxyaddr(req, compileTrust(settings.trustProxy))
  }

  const testExplicitIp = (ip, constraint, mode) => {
    if (ip === constraint) {
      return mode === 'allow'
    } else {
      return mode === 'deny'
    }
  }

  const testCidrBlock = (ip, constraint, mode) => {
    if (rangeCheck.inRange(ip, constraint)) {
      return mode === 'allow'
    } else {
      return mode === 'deny'
    }
  }

  const testRange = (ip, constraint, mode) => {
    const filteredSet = _.filter(getIps(), (constraint) => {
      if (constraint.length > 1) {
        const startIp = iputil.toLong(constraint[0])
        const endIp = iputil.toLong(constraint[1])
        const longIp = iputil.toLong(ip)
        return longIp >= startIp && longIp <= endIp
      } else {
        return ip === constraint[0]
      }
    })

    if (filteredSet.length > 0) {
      return mode === 'allow'
    } else {
      return mode === 'deny'
    }
  }

  const testIp = function (ip, mode) {
    const constraint = this

    // Check if it is an array or a string
    if (typeof constraint === 'string') {
      if (rangeCheck.isRange(constraint)) {
        return testCidrBlock(ip, constraint, mode)
      } else {
        return testExplicitIp(ip, constraint, mode)
      }
    }

    if (typeof constraint === 'object') {
      return testRange(ip, constraint, mode)
    }
  }

  const matchClientIp = (ip) => {
    const mode = settings.mode.toLowerCase()

    const result = _.invokeMap(getIps(), testIp, ip, mode)

    if (mode === 'allow') {
      return _.some(result)
    } else {
      return _.every(result)
    }
  }

  const error = (ip, next) => {
    const err = new IpDeniedError('Access denied to IP address: ' + ip, { ip })
    return next(err)
  }

  return (req, res, next) => {
    if (settings.excluding.length > 0) {
      const results = _.filter(settings.excluding, (exclude) => {
        const regex = new RegExp(exclude)
        return regex.test(req.url)
      })

      if (results.length > 0) {
        if (settings.log && settings.logLevel !== 'deny') {
          settings.logF('Access granted for excluded path: ' + results[0])
        }
        return next()
      }
    }

    const _ips = getIps()
    if (!_ips || !_ips.length) {
      if (settings.mode == 'allow') {
        // ip list is empty, thus no one allowed
        return error('0.0.0.0/0', next)
      } else {
        // there are no blocked ips, skip
        return next()
      }
    }

    const ip = settings.detectIp(req)

    if (matchClientIp(ip, req)) {
      // Grant access
      if (settings.log && settings.logLevel !== 'deny') {
        settings.logF('Access granted to IP address: ' + ip)
      }

      return next()
    }

    // Deny access
    if (settings.log && settings.logLevel !== 'allow') {
      settings.logF('Access denied to IP address: ' + ip)
    }

    return error(ip, next)
  }
}
