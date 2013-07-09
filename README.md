`safe_httplib` is a replacement for the python standard library module `httplib` which attempts to be more secure by design. Specifically, it overrides the HTTPSConnection class to do server-name verification and CA certificate checking.

In general, you should be able to just replace all imports of `httplib` with imports of `safe_httplib` and everything will work.

Due to limitations of the python `ssl` module, this is rather substantially slower than using the base HTTPSConnection.
