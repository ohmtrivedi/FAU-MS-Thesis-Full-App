/* Author: Ohm Trivedi */
/* API Plugin */ 

// const util = require('util');

module.exports = function api(options) {
	let seneca = this;
	
	seneca.add('role:api,path:msOne', function (msg, respond) {
		// console.log(msg);
		let { operation } = msg.args.params;
		let { target } = msg.args.query;
		// let operation = msg.args.body.operation;
        // let target = msg.args.body.remote_ip;
        if (operation == 'fpOS') {
            seneca.act({ role: 'msOne', cmd: 'fpOS', remoteIP: target }, function (err, result) {
				if (err) throw err;
				// result.then(output => respond(output));
				let curTimestamp = new Date();
				console.log(`[${curTimestamp.toLocaleString()}] msOne -> fpOS request completed.`);
				respond(result);
			});
        } else if (operation == 'getCVEs') {
            seneca.act({ role: 'msOne', cmd: 'getCVEs', osQuery: target }, function (err, result) {
				if (err) throw err;
				// result.then(output => respond(output));
				let curTimestamp = new Date();
				console.log(`[${curTimestamp.toLocaleString()}] msOne -> getCVEs request completed.`);
				respond(result);
			});
        }
	});

	seneca.add('role:api,path:msTwo', function (msg, respond) {
		let { operation } = msg.args.params;

		if (operation == 'start') {
			seneca.act({ role: 'msTwo', cmd: 'start' }, function (err, result) {
				if (err) throw err;
				let curTimestamp = new Date();
				console.log(`[${curTimestamp.toLocaleString()}] msTwo -> start request completed.`);
				respond(result);
			});
		} else if (operation == 'updateSLA') {
			seneca.act({ role: 'msTwo', cmd: 'getLogs', type: 'StatelessAttack' }, function (err, result) {
				if (err) throw err;
				let curTimestamp = new Date();
				console.log(`[${curTimestamp.toLocaleString()}] msTwo -> updateSLA request completed.`);
				respond(result);
			}); 
		} else if (operation == 'updateSFA') {
			seneca.act({ role: 'msTwo', cmd: 'getLogs', type: 'StatefullAttack' }, function (err, result) {
				if (err) throw err;
				let curTimestamp = new Date();
				console.log(`[${curTimestamp.toLocaleString()}] msTwo -> updateSFA request completed.`);
				respond(result);
			}); 
		} else if (operation == 'stop') {
			seneca.act({ role: 'msTwo', cmd: 'stop' }, function (err, result) {
				if (err) throw err;
				let curTimestamp = new Date();
				console.log(`[${curTimestamp.toLocaleString()}] msTwo -> stop request completed.`);
				respond(result);
			});
		}
	});

	seneca.add('role:api,path:msThree', function (msg, respond) {
		let { operation } = msg.args.params;
		let { fileName } = msg.args.query;

		if (operation == 'analyzePCAP') {
			seneca.act({ role: 'msThree', cmd: 'analyzePCAP', fileName }, function (err, result) {
				if (err) throw err;
				let curTimestamp = new Date();
				console.log(`[${curTimestamp.toLocaleString()}] msThree -> analyzePCAP request completed.`);
				respond(result);
			});
		}
	});
}
