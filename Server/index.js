/* Author: Ohm Trivedi */
/* Microservice Client */

'use strict'

const Seneca = require('seneca'),
	SenecaWeb = require('seneca-web'),
	Express = require('express'),
	ExpressAdapter = require('seneca-web-adapter-express'),
	Routes = require('./apiRoutes'),
	formidable = require('formidable'),
    fs = require('fs');

const expressApp = Express();

expressApp.use(require('body-parser').json());

expressApp.post('/fileupload', (req, res) => {
	// console.log(req);
	let form = new formidable.IncomingForm();
	form.parse(req, (err, fields, files) => {
		// console.log(request);
		// console.log(files);
		let oldpath = files.file.path;
		let newpath = `${__dirname}/msThree/uploads/` + files.file.name;
		fs.rename(oldpath, newpath, (err) => {
			if (err) {
				res.sendStatus(500);
				res.end();
				throw err;
			}
			res.sendStatus(200);
			res.end();
			let curTimestamp = new Date();
			console.log(`[${curTimestamp.toLocaleString()}] File ${files.file.name} uploaded and moved successfully.`);
		});
	});
});

let senecaWebConfig = {
	routes: Routes,
  	context: expressApp,
  	adapter: ExpressAdapter,
  	options: { parseBody: false }
};

const request_timeout = 300000;

let seneca = Seneca({
		tag: 'expressAPI',
		timeout: request_timeout,
		transport: { 
			web: { timeout: request_timeout } 
		}
	})
	.use('api')
	.use(SenecaWeb, senecaWebConfig)
	.use('balance-client')
	.client({ type: 'balance' })
	// .client({ host: 'localhost', port: 10101, pin: 'role:msOne' })
	.client({ host: 'localhost', port: 10101 })
	.client({ host: 'localhost', port: 10102 })
	.client({ host: 'localhost', port: 10103, pin: 'role:msTwo' })
	.client({ host: 'localhost', port: 10104, pin: 'role:msThree' })
	.ready(() => {
		let server = seneca.export('web/context')();

		server.listen('80', (err) => {
			if (err) throw err;
			console.log('App started on port 80');
		});
	});
