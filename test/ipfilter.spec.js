'use strict'

const IpFilter = require('../index').IpFilter
const IpDeniedError = require('../index').IpDeniedError

const checkError = (ipfilter, req, done) => {
  const next = function next(err) {
    expect(err).toBeInstanceOf(IpDeniedError)
    done()
  }

  ipfilter(req, () => {}, next)
}

let ipfilter
let req

describe('enforcing IP address blacklist restrictions', () => {
  beforeEach(() => {
    ipfilter = IpFilter(['127.0.0.1'], { log: false, trustProxy: true })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }
  })

  it('should allow all non-blacklisted ips', done => {
    req.connection.remoteAddress = '127.0.0.2'
    ipfilter(req, {}, () => {
      done()
    })
  })

  it('should allow all non-blacklisted IPv6 ips', done => {
    req.connection.remoteAddress = '::1'
    ipfilter(req, {}, () => {
      done()
    })
  })

  it('should allow all non-blacklisted IPv4 ips through the IPv6 standard', done => {
    req.connection.remoteAddress = '::ffff:127.0.0.2'
    ipfilter(req, {}, () => {
      done()
    })
  })

  it('should allow all non-blacklisted forwarded ips', done => {
    req.headers['x-forwarded-for'] = '127.0.0.2'
    ipfilter(req, {}, () => {
      done()
    })
  })

  it('should allow all multiple non-blacklisted forwarded ips', done => {
    req.headers['x-forwarded-for'] = '127.0.0.2 127.0.0.3'
    ipfilter(req, {}, () => {
      done()
    })
  })

  it('should deny all blacklisted ips', done => {
    req.connection.remoteAddress = '127.0.0.1'
    checkError(ipfilter, req, done)
  })

  it('should deny all blacklisted forwarded ips', done => {
    req.headers['x-forwarded-for'] = '127.0.0.1'
    checkError(ipfilter, req, done)
  })

  it('should deny all blacklisted ips when no options passed', done => {
    ipfilter = IpFilter(['127.0.0.1'])
    req.connection.remoteAddress = '127.0.0.1'
    checkError(ipfilter, req, done)
  })
})

describe('with no ips', () => {
  beforeEach(() => {
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: '127.0.0.1'
      }
    }
  })

  describe('with a whitelist', () => {
    beforeEach(() => {
      ipfilter = IpFilter([], { mode: 'allow', log: true })
    })

    it('should deny', done => {
      checkError(ipfilter, req, done)
    })
  })

  describe('with a blacklist', () => {
    beforeEach(() => {
      ipfilter = IpFilter([], { mode: 'deny', log: true })
    })

    it('should allow', done => {
      ipfilter(req, {}, () => done())
    })
  })

  it('undefined ips', done => {
    ipfilter = IpFilter(undefined, { mode: 'allow', log: true })
    ipfilter(req, {}, () => done())
  })
})

describe('enforcing IP address whitelist restrictions', () => {
  describe('with a whitelist with ips', () => {
    beforeEach(() => {
      ipfilter = IpFilter(['127.0.0.1'], {
        log: false,
        mode: 'allow',
        trustProxy: true
      })
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should allow whitelisted ips', done => {
      req.connection.remoteAddress = '127.0.0.1'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should allow whitelisted forwarded ips', done => {
      req.headers['x-forwarded-for'] = '127.0.0.1'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should allow whitelisted port ips', done => {
      req.connection.remoteAddress = '127.0.0.1:84849'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should deny all non-whitelisted ips', done => {
      req.connection.remoteAddress = '127.0.0.2'
      checkError(ipfilter, req, done)
    })

    it('should deny all non-whitelisted forwarded ips', done => {
      req.headers['x-forwarded-for'] = '127.0.0.2'
      checkError(ipfilter, req, done)
    })
  })
})

describe('using cidr block', () => {
  describe('enforcing whitelist restrictions', () => {
    beforeEach(() => {
      // Ip range: 127.0.0.1 - 127.0.0.14
      ipfilter = IpFilter(['127.0.0.1/28'], {
        log: false,
        mode: 'allow',
        trustProxy: true
      })
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should allow whitelisted ips', done => {
      req.connection.remoteAddress = '127.0.0.1'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should allow whitelisted forwarded ips', done => {
      req.headers['x-forwarded-for'] = '127.0.0.1'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should allow whitelisted forwarded ips with ports', done => {
      req.headers['x-forwarded-for'] = '127.0.0.1:23456'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should deny all non-whitelisted ips', done => {
      req.connection.remoteAddress = '127.0.0.17'
      checkError(ipfilter, req, done)
    })

    it('should deny all non-whitelisted forwarded ips', done => {
      req.headers['x-forwarded-for'] = '127.0.0.17'
      checkError(ipfilter, req, done)
    })
  })

  describe('enforcing IP address blacklist restrictions', () => {
    beforeEach(() => {
      ipfilter = IpFilter(['127.0.0.1/28'], {
        log: false,
        trustProxy: true
      })
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should allow all non-blacklisted ips', done => {
      req.connection.remoteAddress = '127.0.0.17'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should allow all non-blacklisted forwarded ips', done => {
      req.headers['x-forwarded-for'] = '127.0.0.17'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should deny all blacklisted ips', done => {
      req.connection.remoteAddress = '127.0.0.1'
      checkError(ipfilter, req, done)
    })

    it('should deny all blacklisted forwarded ips', done => {
      req.headers['x-forwarded-for'] = '127.0.0.1'
      checkError(ipfilter, req, done)
    })
  })

  describe('enforcing private ip restrictions', () => {
    beforeEach(() => {
      ipfilter = IpFilter(['127.0.0.1/28'], {
        log: false,
        allowPrivateIPs: true
      })
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should allow all private ips', done => {
      req.connection.remoteAddress = '10.0.0.0'
      ipfilter(req, {}, () => {
        done()
      })
    })
  })
})

describe('using ranges', () => {
  describe('enforcing whitelist restrictions', () => {
    beforeEach(() => {
      // Ip range: 127.0.0.1 - 127.0.0.14
      ipfilter = IpFilter([['127.0.0.1', '127.0.0.3']], {
        log: false,
        mode: 'allow',
        trustProxy: true
      })
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should allow whitelisted ips', done => {
      req.connection.remoteAddress = '127.0.0.1'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should allow whitelisted ips with port numbers', done => {
      req.connection.remoteAddress = '127.0.0.1:93923'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should allow whitelisted forwarded ips', done => {
      req.headers['x-forwarded-for'] = '127.0.0.1'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should allow whitelisted forwarded ips with ports', done => {
      req.headers['x-forwarded-for'] = '127.0.0.1:23456'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should deny all non-whitelisted ips', done => {
      req.connection.remoteAddress = '127.0.0.17'
      checkError(ipfilter, req, done)
    })

    it('should deny all non-whitelisted ips with ports', done => {
      req.connection.remoteAddress = '127.0.0.17:23456'
      checkError(ipfilter, req, done)
    })

    it('should deny all non-whitelisted forwarded ips', done => {
      req.headers['x-forwarded-for'] = '127.0.0.17'
      checkError(ipfilter, req, done)
    })

    it('should deny all non-whitelisted forwarded ips with ports', done => {
      req.headers['x-forwarded-for'] = '127.0.0.17:23456'
      checkError(ipfilter, req, done)
    })
  })

  describe('enforcing ip restrictions with only one ip in the range', () => {
    beforeEach(() => {
      // Ip range: 127.0.0.1 - 127.0.0.14
      ipfilter = IpFilter([['127.0.0.1']], { log: false, mode: 'allow' })
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should allow whitelisted ips', done => {
      req.connection.remoteAddress = '127.0.0.1'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should deny all non-whitelisted ips', done => {
      req.connection.remoteAddress = '127.0.0.17'
      checkError(ipfilter, req, done)
    })
  })

  describe('enforcing IP address blacklist restrictions', () => {
    beforeEach(() => {
      ipfilter = IpFilter([['127.0.0.1', '127.0.0.3']], {
        log: false,
        trustProxy: true
      })
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should allow all non-blacklisted ips', done => {
      req.connection.remoteAddress = '127.0.0.17'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should allow all non-blacklisted forwarded ips', done => {
      req.headers['x-forwarded-for'] = '127.0.0.17'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should deny all blacklisted ips', done => {
      req.connection.remoteAddress = '127.0.0.1'
      checkError(ipfilter, req, done)
    })

    it('should deny all blacklisted forwarded ips', done => {
      req.headers['x-forwarded-for'] = '127.0.0.1'
      checkError(ipfilter, req, done)
    })
  })

  describe('enforcing private ip restrictions', () => {
    beforeEach(() => {
      ipfilter = IpFilter([['127.0.0.1', '127.0.0.3']], {
        log: false,
        allowPrivateIPs: true
      })
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should allow all private ips', done => {
      req.connection.remoteAddress = '10.0.0.0'
      ipfilter(req, {}, () => {
        done()
      })
    })
  })
})

describe('disabling forward headers', () => {
  beforeEach(() => {
    ipfilter = IpFilter(['127.0.0.1'], { log: false, allowedHeaders: [] })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }
  })

  it('should deny all non-blacklisted forwarded ips', done => {
    req.connection.remoteAddress = '127.0.0.1'
    req.headers['x-forwarded-for'] = '127.0.0.2'
    checkError(ipfilter, req, done)
  })
})

describe('enabling cloudflare headers', () => {
  beforeEach(() => {
    ipfilter = IpFilter(['127.0.0.1'], {
      log: false,
      allowedHeaders: ['cf-connecting-ip']
    })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }
  })

  it('should allow all non-blacklisted forwarded ips', done => {
    req.connection.remoteAddress = '127.0.0.1'
    req.headers['cf-connecting-ip'] = '127.0.0.2'
    ipfilter(req, {}, () => {
      done()
    })
  })
})

describe('disabling cloudflare headers', () => {
  beforeEach(() => {
    ipfilter = IpFilter(['127.0.0.1'], { log: false, allowedHeaders: [] })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }
  })

  it('should deny all non-blacklisted forwarded ips', done => {
    req.connection.remoteAddress = '127.0.0.1'
    req.headers['cf-connecting-ip'] = '127.0.0.2'
    checkError(ipfilter, req, done)
  })
})

describe('excluding certain routes from filtering', () => {
  beforeEach(() => {
    ipfilter = IpFilter(['127.0.0.1'], {
      log: false,
      mode: 'allow',
      excluding: ['/foo.*']
    })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      },
      url: '/foo?bar=123'
    }
  })

  it('should allow requests to excluded paths', done => {
    req.connection.remoteAddress = '190.0.0.0'
    ipfilter(req, {}, () => {
      done()
    })
  })

  it('should deny requests to other paths', done => {
    req.url = '/bar'
    req.connection.remoteAddress = '190.0.0.0'
    checkError(ipfilter, req, done)
  })
})

describe('no ip address can be found', () => {
  beforeEach(() => {
    ipfilter = IpFilter(['127.0.0.1'], {
      log: false,
      mode: 'allow',
      excluding: ['/foo.*']
    })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }
  })

  it('should deny requests', done => {
    req.url = '/bar'
    req.connection.remoteAddress = ''
    checkError(ipfilter, req, done)
  })
})

describe('external logger function', () => {
  it('should log to a passed logger exactly one message', done => {
    const messages = []
    const logF = message => messages.push(message)
    ipfilter = IpFilter(['127.0.0.1'], { log: true, logF: logF })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: '127.0.0.1'
      }
    }

    const next = () => {
      expect(messages.length).toBe(1)
      done()
    }

    ipfilter(req, () => {}, next)
  })

  it('should log to a passed logger the correct message', done => {
    const messages = []
    const logF = message => messages.push(message)
    ipfilter = IpFilter(['127.0.0.1'], { log: true, logF: logF })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }

    req.connection.remoteAddress = '127.0.0.1'

    const next = () => {
      expect(messages[0]).toBe('Access denied to IP address: 127.0.0.1')
      done()
    }

    ipfilter(req, () => {}, next)
  })
})

describe('LogLevel function', () => {
  it('should log deny if log level is set to default', done => {
    const messages = []
    const logF = message => messages.push(message)
    ipfilter = IpFilter(['127.0.0.1'], { log: true, logF: logF })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }

    req.connection.remoteAddress = '127.0.0.1'

    const next = () => {
      expect(messages[0]).toBe('Access denied to IP address: 127.0.0.1')
      done()
    }

    ipfilter(req, () => {}, next)
  })

  it('should log allow if log level is set to default', done => {
    const messages = []
    const logF = message => messages.push(message)
    ipfilter = IpFilter(['127.0.0.1'], { log: true, logF: logF })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }

    req.connection.remoteAddress = '127.0.0.2'

    const next = () => {
      expect(messages[0]).toBe('Access granted to IP address: 127.0.0.2')
      done()
    }

    ipfilter(req, () => {}, next)
  })

  it('should log deny if log level is set to all', done => {
    const messages = []
    const logF = message => messages.push(message)
    ipfilter = IpFilter(['127.0.0.1'], {
      log: true,
      logF: logF,
      logLevel: 'all'
    })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }

    req.connection.remoteAddress = '127.0.0.1'

    const next = () => {
      expect(messages[0]).toBe('Access denied to IP address: 127.0.0.1')
      done()
    }

    ipfilter(req, () => {}, next)
  })

  it('should log allow if log level is set to all', done => {
    const messages = []
    const logF = message => messages.push(message)
    ipfilter = IpFilter(['127.0.0.1'], {
      log: true,
      logF: logF,
      logLevel: 'all'
    })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }

    req.connection.remoteAddress = '127.0.0.2'

    const next = () => {
      expect(messages[0]).toBe('Access granted to IP address: 127.0.0.2')
      done()
    }

    ipfilter(req, () => {}, next)
  })

  it('should log allow if log level is set to allow', done => {
    const messages = []
    const logF = message => messages.push(message)
    ipfilter = IpFilter(['127.0.0.1'], {
      log: true,
      logF: logF,
      logLevel: 'allow'
    })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }

    req.connection.remoteAddress = '127.0.0.2'

    const next = () => {
      expect(messages[0]).toBe('Access granted to IP address: 127.0.0.2')
      done()
    }

    ipfilter(req, () => {}, next)
  })

  it('should not log deny if log level is set to allow', done => {
    const messages = []
    const logF = message => messages.push(message)
    ipfilter = IpFilter(['127.0.0.1'], {
      log: true,
      logF: logF,
      logLevel: 'allow'
    })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }

    req.connection.remoteAddress = '127.0.0.1'

    const next = () => {
      expect(messages.length).toBe(0)
      done()
    }

    ipfilter(req, () => {}, next)
  })

  it('should not log allow if log level is set to deny', done => {
    const messages = []
    const logF = message => messages.push(message)
    ipfilter = IpFilter(['127.0.0.1'], {
      log: true,
      logF: logF,
      logLevel: 'deny'
    })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }

    req.connection.remoteAddress = '127.0.0.2'

    const next = () => {
      expect(messages.length).toBe(0)
      done()
    }

    ipfilter(req, () => {}, next)
  })

  it('should not log allow if log level is set to deny and a exclude path is set', done => {
    const messages = []
    const logF = message => {
      console.log(message, 'it happend!')
      messages.push(message)
    }
    ipfilter = IpFilter(['127.0.0.1'], {
      log: true,
      logF: logF,
      logLevel: 'deny',
      excluding: ['/health']
    })
    req = {
      url: '/health/foo/bar',
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }

    req.connection.remoteAddress = '127.0.0.1'

    const next = () => {
      expect(messages.length).toBe(0)
      done()
    }

    ipfilter(req, () => {}, next)
  })

  it('should log deny if log level is set to deny', done => {
    const messages = []
    const logF = message => messages.push(message)
    ipfilter = IpFilter(['127.0.0.1'], {
      log: true,
      logF: logF,
      logLevel: 'deny'
    })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }

    req.connection.remoteAddress = '127.0.0.1'

    const next = () => {
      expect(messages[0]).toBe('Access denied to IP address: 127.0.0.1')
      done()
    }

    ipfilter(req, () => {}, next)
  })

  it('should log allow if log level is set to allow and excluded path is set', done => {
    const messages = []
    const logF = message => messages.push(message)
    ipfilter = IpFilter(['127.0.0.1'], {
      log: true,
      logF: logF,
      mode: 'allow',
      excluding: ['/foo.*']
    })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      },
      url: '/foo?bar=123'
    }
    req.connection.remoteAddress = '190.0.0.0'
    ipfilter(req, {}, () => {
      expect(messages.length).toBe(1)
      expect(messages[0]).toBe('Access granted for excluded path: /foo.*')
      done()
    })
  })
})

describe('an array of cidr blocks', () => {
  describe('blacklist', () => {
    beforeEach(() => {
      ipfilter = IpFilter(['72.30.0.0/26', '127.0.0.1/24'], {
        mode: 'deny',
        log: false
      })
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should deny all blacklisted ips', done => {
      req.connection.remoteAddress = '127.0.0.1'
      checkError(ipfilter, req, done)
    })
  })

  describe('whitelist', () => {
    beforeEach(() => {
      ipfilter = IpFilter(['72.30.0.0/26', '127.0.0.1/24'], {
        mode: 'allow',
        log: false
      })
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should allow all whitelisted ips', done => {
      req.connection.remoteAddress = '127.0.0.1'
      ipfilter(req, {}, () => {
        done()
      })
    })
  })
})

describe('mixing different types of filters', () => {
  describe('with a whitelist', () => {
    beforeEach(() => {
      ipfilter = IpFilter(
        ['127.0.0.1', '192.168.1.3/28', ['127.0.0.3', '127.0.0.35']],
        { cidr: true, mode: 'allow', log: false }
      )
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should allow explicit ips', done => {
      req.connection.remoteAddress = '127.0.0.1'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should allow ips in a cidr block', done => {
      req.connection.remoteAddress = '192.168.1.1'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should allow ips in a range', done => {
      req.connection.remoteAddress = '127.0.0.20'
      ipfilter(req, {}, () => {
        done()
      })
    })
  })

  describe('with a blacklist', () => {
    beforeEach(() => {
      ipfilter = IpFilter(
        ['127.0.0.1', '192.168.1.3/28', ['127.0.0.3', '127.0.0.35']],
        { mode: 'deny', log: false }
      )
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should deny explicit ips', done => {
      req.connection.remoteAddress = '127.0.0.1'
      checkError(ipfilter, req, done)
    })

    it('should deny ips in a cidr block', done => {
      req.connection.remoteAddress = '192.168.1.15'
      checkError(ipfilter, req, done)
    })

    it('should deny ips in a range', done => {
      req.connection.remoteAddress = '127.0.0.15'
      checkError(ipfilter, req, done)
    })
  })
})

describe('mixing different types of filters with IPv4 and IPv6', () => {
  const ips = [
    '127.0.0.1',
    '192.168.1.3/28',
    '2001:4860:8006::62',
    '2001:4860:8007::62/64',
    ['127.0.0.3', '127.0.0.35']
  ]

  describe('with a whitelist', () => {
    beforeEach(() => {
      ipfilter = IpFilter(ips, { cidr: true, mode: 'allow', log: false })
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should allow explicit IPv4 ips', done => {
      req.connection.remoteAddress = '127.0.0.1'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should allow IPv4 ips in a cidr block', done => {
      req.connection.remoteAddress = '192.168.1.1'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should allow IPv4 ips in a range', done => {
      req.connection.remoteAddress = '127.0.0.20'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should allow explicit IPv6 ips', done => {
      req.connection.remoteAddress = '2001:4860:8006::62'
      ipfilter(req, {}, () => {
        done()
      })
    })

    it('should allow IPv6 ips in a cidr block', done => {
      req.connection.remoteAddress = '2001:4860:8007:0::62'
      ipfilter(req, {}, () => {
        done()
      })
    })
  })

  describe('with a blacklist', () => {
    beforeEach(() => {
      ipfilter = IpFilter(ips, { mode: 'deny', log: false })
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should deny explicit ips', done => {
      req.connection.remoteAddress = '127.0.0.1'
      checkError(ipfilter, req, done)
    })

    it('should deny ips in a cidr block', done => {
      req.connection.remoteAddress = '192.168.1.15'
      checkError(ipfilter, req, done)
    })

    it('should deny explicit IPv6 ips', done => {
      req.connection.remoteAddress = '2001:4860:8006::62'
      checkError(ipfilter, req, done)
    })

    it('should deny IPv6 ips in a cidr block', done => {
      req.connection.remoteAddress = '2001:4860:8007:0::62'
      checkError(ipfilter, req, done)
    })

    it('should deny ips in a range', done => {
      req.connection.remoteAddress = '127.0.0.15'
      checkError(ipfilter, req, done)
    })
  })
})

describe('using a custom ip detection function', () => {
  beforeEach(() => {
    function detectIp(req) {
      const ipAddress = req.connection.remoteAddress.replace(/\//g, '.')

      return ipAddress
    }

    ipfilter = IpFilter(['127.0.0.1'], {
      detectIp: detectIp,
      log: false,
      allowedHeaders: ['x-forwarded-for']
    })
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }
  })

  it('should find the ip correctly', done => {
    req.connection.remoteAddress = '127/0/0/1'
    checkError(ipfilter, req, done)
  })
})

describe('using ips as a function', () => {
  const ips = () => {
    return ['127.0.0.1']
  }

  describe('with a whitelist', () => {
    beforeEach(() => {
      ipfilter = IpFilter(ips, { mode: 'allow', log: false })
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should allow', done => {
      req.connection.remoteAddress = '127.0.0.1'
      ipfilter(req, {}, () => {
        done()
      })
    })
    it('should deny', done => {
      req.connection.remoteAddress = '127.0.0.2'
      checkError(ipfilter, req, done)
    })
  })

  describe('with a blacklist', () => {
    beforeEach(() => {
      ipfilter = IpFilter(ips, { mode: 'deny', log: false })
      req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      }
    })

    it('should allow', done => {
      req.connection.remoteAddress = '127.0.0.2'
      ipfilter(req, {}, () => {
        done()
      })
    })
    it('should deny', done => {
      req.connection.remoteAddress = '127.0.0.1'
      checkError(ipfilter, req, done)
    })
  })
})

describe('compiled trust', () => {
  beforeEach(() => {
    req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    }
  })

  it('trust proxy function', done => {
    ipfilter = IpFilter('127.0.0.1', {
      mode: 'deny',
      log: false,
      trustProxy: () => true
    })
    req.connection.remoteAddress = '127.0.0.1'
    ipfilter(req, {}, () => {
      done()
    })
  })

  it('trust proxy with 5 hops', done => {
    ipfilter = IpFilter('127.0.0.1', {
      mode: 'deny',
      log: false,
      trustProxy: 5
    })
    req.connection.remoteAddress = '127.0.0.1'
    ipfilter(req, {}, () => {
      done()
    })
  })

  it('trust proxy strings', done => {
    ipfilter = IpFilter('127.0.0.1', {
      mode: 'deny',
      log: false,
      trustProxy: '127.0.0.1,127.0.0.2'
    })
    req.connection.remoteAddress = '127.0.0.1'
    ipfilter(req, {}, () => {
      done()
    })
  })
})

describe('deniedError', () => {
  it('should have custom message', () => {
    const err = new IpDeniedError('custom message')
    expect(err).toBeInstanceOf(IpDeniedError)
    expect(err.message).toBe('custom message')
  })

  it('should have no custom message', () => {
    const err = new IpDeniedError()
    expect(err).toBeInstanceOf(IpDeniedError)
    expect(err.message).toBe('The requesting IP was denied')
  })
})
