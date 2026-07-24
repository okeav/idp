// Convenience re-export — `cookie-parser` is a peerDependency (the consumer's
// app already needs it mounted for req.cookies to exist before this
// package's middleware can read it).
export { default as cookieParser } from 'cookie-parser';
