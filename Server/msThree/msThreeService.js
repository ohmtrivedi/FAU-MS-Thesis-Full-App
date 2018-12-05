/* Author: Ohm Trivedi */
/* Microservice 3 Server */

'use strict'

const request_timeout = 300000;

const Seneca = require('seneca')({
		tag: 'msThreeService',
		timeout: request_timeout,
		transport: { 
			web: { timeout: request_timeout } 
		}
	})
	.use('./msThreePlugin', { message: 'msThree Plugin Added!' })
	.listen({
		host: 'localhost',
		// port: 9093,
		port: process.argv[2] || 10103,
		pin: 'role:msThree'
	});
