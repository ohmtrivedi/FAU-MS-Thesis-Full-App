/* Author: Ohm Trivedi */
/* Plugin for OS-FP (Async) */

'use strict'

const { exec } = require('child_process'),
    rp = require('request-promise'),
    cheerio = require('cheerio');
    // util = require('util');

module.exports = function msOne (options) {
    let seneca = this;
    // let identifiedOS = ''; 

    seneca.add({ init: 'msOne' }, function(pluginInfo, respond) {
        console.log(options.message);
        respond();
    });

    seneca.add({ role: 'msOne', cmd: 'fpOS' }, function (msg, respond) {
        console.log('Msg received here!');
        const { remoteIP } = msg;
        let commandToExec = `sudo nmap -T5 -O ${remoteIP} | grep -m 1 -e "Aggressive OS guesses" -e "OS details" -e "No OS"`;
        exec(commandToExec, (error, stdout, stderr) => {
            let outputSplit, osGuess;
            let curTimestamp = new Date();
            console.log(`[${curTimestamp.toLocaleString()}] Nmap of ${remoteIP} complete!`);
            if (error) {
                console.log(error);
            } else if (stderr) {
                console.log(stderr);
            } else if (stdout.startsWith('Aggressive')) {
                outputSplit = stdout.slice(22).split(',');
                osGuess = outputSplit[0].trim();
            } else if (stdout.startsWith('OS')) {
                outputSplit = stdout.slice(11).split(',');
                osGuess = outputSplit[0].trim();
            } else {
                osGuess = stdout.trim();
            }
            if (osGuess.indexOf('(') != -1) {
                osGuess = osGuess.substring(0, osGuess.indexOf('(')-1);
            }
            respond(null, { osGuess });  
        });
    });

    seneca.add({ role: 'msOne', cmd: 'getCVEs' }, async function (msg, respond) {
        let { osQuery } = msg;
        let osCVEs = await scrapCVEs(osQuery);
        console.log(`Response: Found ${osCVEs.cve_id.length} CVEs.`);
        respond(null, osCVEs);
    });
}

let scrapCVEs = (osQuery) => {
    let osName = osQuery.split(' ');
    let url = 'http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=' + osName.join('+');
    let os_cves = { cve_id: [], cve_desc: [] };

    const options = {
        uri: url,
        transform: function(body) {
            return cheerio.load(body);
        }
    };

    return rp(options)
            .then($ => {
                let desiredTableElem = $('#TableWithRules').children('table');
                desiredTableElem.find('td').each((i, elem) => {
                    // console.log(i + elem.name);
                    if (elem.children[0].type === 'tag') {
                        // console.log(elem.children[0].name);
                        os_cves.cve_id.push(elem.children[0].children[0].data);
                        // console.log(elem.children[0].children[0].data);
                    }
                    else if (elem.children[0].type === 'text') {
                        os_cves.cve_desc.push(elem.children[0].data);
                        // console.log(elem.children[0].data);
                    }
                });
                console.log('Scrapping complete!');
                return os_cves;
            })
            .catch(err => {
                console.log(err);
            });
}