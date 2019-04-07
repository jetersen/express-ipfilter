module.exports = class IpDeniedError extends Error {
  constructor(message, extra) {
    message = message || 'The requesting IP was denied'
    super(message)
    this.message = message
    this.name = this.constructor.name
    Error.captureStackTrace(this, this.constructor)
    this.extra = extra
    this.status = this.statusCode = 403
  }
}
