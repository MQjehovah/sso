/** 业务语义的 HTTP 错误(带状态码) */
export class HttpError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}
