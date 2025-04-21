/**
 * Error class representing an unsupported operation or feature.
 */
export class UnsupportedError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'UnsupportedError';
  }
}
