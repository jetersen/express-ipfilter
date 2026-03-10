/*!
 * Express - IP Filter
 * Copyright(c) 2014 Bradley and Montgomery Inc.
 * MIT Licensed
 */

'use strict'

/**
 * Module dependencies.
 */
const iputil = require('neoip')
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

  const getIps =
    typeof ips === 'function' ? ips : () => (Array.isArray(ips) ? ips : [ips])
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

  const settings = {
    mode: 'deny',
    log: true,
    logF: logger,
    excluding: [],
    trustProxy: false, // This is the default used by express.
    ...opts,
  }

  if (typeof settings.detectIp !== 'function') {
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

  const stripPort = (ip) => {
    // Strip port from IPv4 addresses (e.g. 127.0.0.1:3000 -> 127.0.0.1)
    const portMatch = ip.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$/)
    return portMatch ? portMatch[1] : ip
  }

  const compareIps = (a, b) => {
    const ba = iputil.toUInt8Array(a)
    const bb = iputil.toUInt8Array(b)
    if (ba.length !== bb.length) return ba.length - bb.length
    for (let i = 0; i < ba.length; i++) {
      if (ba[i] !== bb[i]) return ba[i] - bb[i]
    }
    return 0
  }

  const testRange = (ip, constraint, mode) => {
    const cleanIp = stripPort(ip)
    const filteredSet = getIps().filter((constraint) => {
      if (constraint.length > 1) {
        return (
          compareIps(cleanIp, constraint[0]) >= 0 &&
          compareIps(cleanIp, constraint[1]) <= 0
        )
      } else {
        return cleanIp === constraint[0]
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

    const result = getIps().map((constraint) =>
      testIp.call(constraint, ip, mode),
    )

    if (mode === 'allow') {
      return result.some((r) => r)
    } else {
      return result.every((r) => r)
    }
  }

  const error = (ip, next) => {
    const err = new IpDeniedError('Access denied to IP address: ' + ip, { ip })
    return next(err)
  }

  return (req, res, next) => {
    if (settings.excluding.length > 0) {
      const results = settings.excluding.filter((exclude) => {
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
