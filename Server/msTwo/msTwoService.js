/* Author: Ohm Trivedi */
/* Microservice 2 Server */

'use strict'

const request_timeout = 300000;

const Seneca = require('seneca')({
		tag: 'msTwoService',
		timeout: request_timeout,
		transport: { 
			web: { timeout: request_timeout } 
		}
	})
	.use('./msTwoPlugin', { message: 'msTwo Plugin Added!' })
	.listen({
		host: 'localhost',
		// port: 9092,
		port: process.argv[2] || 10103,
		pin: 'role:msTwo'
	});
