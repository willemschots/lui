# lui: Go convenience wrapper around net/http

[![Build Status](http://img.shields.io/github/workflow/status/willemschots/lui/Testing/main)][workflow]
[![Go Documentation](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)][godocs]

[workflow]: https://github.com/willemschots/lui/actions
[godocs]: https://godoc.org/github.com/willemschots/lui

For when you just want to write http handlers and call it a day.

Lui is a convenience wrapper around net/http. It provides:
 - Quick methods for setting up http/https servers
 - Graceful shutdowns
 - Optional config file support (TODO)

 ## Why 'lui'?

 'Lui' means 'lazy' in Dutch. Instead of implementing a server
 for each project I can be lazy and use this package.