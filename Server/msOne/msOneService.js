/* Author: Ohm Trivedi */
/* Microservice 1 Server */

'use strict'

const request_timeout = 300000;

const Seneca = require('seneca')({
		tag: 'msOneService',
		timeout: request_timeout,
		transport: { 
			web: { timeout: request_timeout } 
		}
	})
	.use('./msOnePlugin', { message: 'msOne Plugin Added!' })
	.listen({
		host: 'localhost',
		// port: 9091,
		port: process.argv[2] || 10101,
		pin: 'role:msOne'
	});
