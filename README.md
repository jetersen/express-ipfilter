# express-ipfilter: A light-weight IP address based filtering system

This package provides easy IP based access control. This can be achieved either by denying certain IPs and allowing all others, or allowing certain IPs and denying all others.

## Installation

Recommended installation is with npm. To add express-ipfilter to your project, do:

    npm install express-ipfilter

## Usage with Express

Denying certain IP addresses, while allowing all other IPs:

```javascript
// Init dependencies
const express = require('express')
const ipfilter = require('express-ipfilter').IpFilter

// Deny the following IPs
const ips = ['127.0.0.1']

// Create the server
app.use(ipfilter(ips))
app.listen(3000)
```

Allowing certain IP addresses, while denying all other IPs:

```javascript
// Init dependencies
// Init dependencies
const express = require('express')
const ipfilter = require('express-ipfilter').IpFilter

// Allow the following IPs
const ips = ['127.0.0.1']

// Create the server
app.use(ipfilter(ips, { mode: 'allow' }))

module.exports = app
```

Using CIDR subnet masks for ranges:

```javascript
const ips = ['127.0.0.1/24']

// Create the server
app.use(ipfilter(ips, { mode: 'allow' }))

module.exports = app
```

Using IP ranges:

```javascript
const ips = [['127.0.0.1', '127.0.0.10']]

// Create the server
app.use(ipfilter(ips, { mode: 'allow' }))

module.exports = app
```

Using a function to get Ips:

```javascript
const ips = function() {
  return ['127.0.0.1']
}

// Create the server
app.use(ipfilter(ips, { mode: 'allow' }))

module.exports = app
```

Using wildcard ip ranges and nginx forwarding:

```javascript
  let allowlist_ips = ['10.1.*.*', '123.??.34.8*'] // matches '10.1.76.32' and '123.77.34.89'

  let clientIp = function(req, res) {
    return req.headers['x-forwarded-for'] ? (req.headers['x-forwarded-for']).split(',')[0] : ""
  }
  
  app.use(
    ipFilter({
      detectIp: clientIp,
      forbidden: 'You are not authorized to access this page.',
      filter: allowlist_ips,
    })
  )
```

## Error Handling

When an IP is denied, an IpDeniedError will be thrown by the middleware. If you do not handle the error, it will cause your app to crash due to an unhandled exception. Here is an example of how to handle the error, which can also be found in the example app:

```javascript
if (app.get('env') === 'development') {
  app.use((err, req, res, _next) => {
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
```

You will need to require the `IpDeniedError` type in order to handle it.

## Options

| Property   | Description                                                                                                                                            | Type                                     | Default            |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------- | ------------------ |
| mode       | whether to _deny_ or _allow_ to the IPs provided                                                                                                       | string                                   | deny               |
| log        | console log actions                                                                                                                                    | boolean                                  | true               |
| logLevel   | level of logging (_all_,_deny_,_allow_)                                                                                                                | string                                   | all                |
| excluding  | routes that should be excluded from ip filtering                                                                                                       | array                                    | []                 |
| detectIp   | define a custom function that takes an Express request object and returns an IP address to test against                                                | function                                 | built-in detection |
| trustProxy | This setting is implemented using the proxy-addr package. Check the [documentation](https://www.npmjs.com/package/proxy-addr) for the trust parameter. | boolean, array, string, number, function | false              |

> A note on detectIp

If you need to parse an IP address in a way that is not supported by default, you can write your own parser and pass that to `ipfilter`.

```javascript
const customDetection = req => {
  var ipAddress

  ipAddress = req.connection.remoteAddress.replace(/\//g, '.')

  return ipAddress
}

ipfilter(ips, { detectIp: customDetection })
```

## Contributing

See the `CONTRIBUTING.MD` document for more information on contributing.

### Running Tests

Run tests by using `npm test`

## Changelog

Moved to [GitHub Releases](https://github.com/casz/express-ipfilter/releases)

## Credits

BaM Interactive - [code.bamideas.com](http://code.bamideas.com)
