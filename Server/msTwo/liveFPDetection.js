/* Author: Ohm Trivedi */
/* Live Fingerprinting Attack Detection */

'use strict'

const pcap = require('pcap'),
    { fork } = require('child_process'),
    fs = require('fs'),
    { MongoClient } = require('mongodb'),
    { USERNAME, PASSWORD, SERVER_URL, DATABASE } = require('../common/mongoDBConfig');

process.setMaxListeners(0);

let attackSigns, newSession, attackers, writeStream, logFile;
let SLALogs = '', SFALogs = '';
let pktCounts = {
    totalPkts: 0,
    tcpPkts: 0,
    udpPkts: 0,
    icmpPkts: 0,
    // SYN_ACK: 0,
    statelessAttacks: {
        NULLScan: 0, // No flags set
        PSH: 0,
        SYN_FIN: 0,
        RST_FIN: 0,
        RST_SYN: 0,
        FIN_URG: 0,
        SYN_URG: 0,
        SYN_FIN_URG: 0,
        XMASScan: 0, // URG && PSH && FIN
        SYN_FIN_PSH_URG: 0,
        SYN_ECE_CWR: 0,
        ACK_DF_WS1024: 0,
    },
    statefullAttacks: {
        noSession: 0,
        FINScan: 0, // FIN only
    },
    icmpAttacks: {
        invalidCode: 0,
        invalidType: 0
    }
};

function getSignatures() {
    const MONGO_URL = `mongodb://${USERNAME}:${PASSWORD}@${SERVER_URL}/`;

    let opts = { 
        useNewUrlParser: true,
        authSource: 'admin'
    };
        
    return new Promise((resolve, reject) => {
        MongoClient.connect(MONGO_URL, opts, (err, db) => {
            if (err) throw err;
            let mydb = db.db(DATABASE);
            
            let query = {};

            mydb.collection('attackSigns')
            .find(query, { projection: { _id: 0, attack: 1, sign: 1 } })
            .toArray((err, result) => {
                if (err) reject(err);
                attackSigns = result.reduce((map, obj) => {
                    map[obj.attack] = obj.sign;
                    return map;
                }, {});
                // console.log(attackSigns);
		resolve(attackSigns);
                db.close();
            });
        });
    });
}

function parsePacket(raw_packet) {
    pktCounts.totalPkts++;
    
    let packet = pcap.decode.packet(raw_packet);
    // console.log(packet);
    let packetHeader = packet.pcap_header;
    let pktTimestamp = new Date(packetHeader.tv_sec*1000);

    let ethernetPacket = packet.payload;

    // Check for IPv4
    if (ethernetPacket.ethertype != 2048) { // ipPacket.constructor.name != 'IPv4'
        // console.log(`[${pktTimestamp.toLocaleString()}] Packet #${pktCounts.totalPkts}: Not IPv4, actual - ${ethernetPacket.ethertype}`);
        return;
    }

    // IP packet
    let ipPacket = ethernetPacket.payload;

    // Validate IPv4 Header
    if (ipPacket.version != 4 || (ipPacket.headerLength < 20 && ipPacket.headerLength > 60)) {
    // console.log(`[${pktTimestamp.toLocaleString()}] Packet #${pktCounts.totalPkts}: Invalid IPv4 header`);
        return;
    }
    
    // Protocol
    // let protocol;
    switch (ipPacket.protocol) {
        case 1: // protocol = 'ICMP'
            pktCounts.icmpPkts++;
            parseICMP(ipPacket, pktTimestamp);
            break;
        case 6: // protocol = 'TCP'
            pktCounts.tcpPkts++;
            parseTCP(ipPacket, pktTimestamp);
            break;
        case 17: // protocol = 'UDP'
            pktCounts.udpPkts++;
            // parseUDP();
            break;
        default: // protocol = 'Other'
            // console.log(`[${pktTimestamp.toLocaleString()}] Packet #${pktCounts.totalPkts}: Other Protocol - ${ipPacket.protocol}`);
            return;
    }
    return;
}

function parseTCP(ipPacket, pktTimestamp) {
    // Extracting Source & Destination IP
    let sourceIP = ipPacket.saddr['addr'].join('.');
    let destinationIP = ipPacket.daddr['addr'].join('.');
    // IP Flags
    let ipFlag_DF = ipPacket.flags.doNotFragment;

    // TCP packet
    let tcpPacket = ipPacket.payload;
    // Source Port
    let sourcePort = tcpPacket.sport;
    // Destination Port
    let destinationPort = tcpPacket.dport;
    // Windows size
    let windowSize = tcpPacket.windowSize;
    // TCP Flags
    let tcpFlags = (tcpPacket.flags.fin ? 1 : 0) + (tcpPacket.flags.syn ? 2 : 0)
                + (tcpPacket.flags.rst ? 4 : 0) + (tcpPacket.flags.psh ? 8 : 0)
                + (tcpPacket.flags.ack ? 16 : 0) + (tcpPacket.flags.urg ? 32 : 0)
                + (tcpPacket.flags.ece ? 64 : 0) + (tcpPacket.flags.cwr ? 128 : 0);

    /* Check for Stateless Attacks */
    if (tcpFlags == attackSigns['Null Scan'].tcpFlags) {
        pktCounts.statelessAttacks.NULLScan++;
        writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with no flags ` +
            `set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
        SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with no flags ` +
            `set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if (tcpFlags == attackSigns['SYN-FIN'].tcpFlags) {
        pktCounts.statelessAttacks.SYN_FIN++;
        writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with SYN and ` +
            `FIN flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
        SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with SYN and ` +
            `FIN flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if (tcpFlags == attackSigns['RST-FIN'].tcpFlags) {
        pktCounts.statelessAttacks.RST_FIN++;
        writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with RST and ` +
            `FIN flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
        SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with RST and ` +
            `FIN flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if (tcpFlags == attackSigns['RST-SYN'].tcpFlags) {
        pktCounts.statelessAttacks.RST_SYN++;
        writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with RST and ` +
            `SYN flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
        SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with RST and ` +
            `SYN flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if (tcpFlags == attackSigns['PSH'].tcpFlags) {
        pktCounts.statelessAttacks.PSH++;
        writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet containing ` +
            `only PSH flag to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
        SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet containing ` +
            `only PSH flag to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if (tcpFlags == 18) {
        // pktCounts.SYN_ACK++;
        return;
    } else if (tcpFlags == attackSigns['FIN-URG'].tcpFlags) {
        pktCounts.statelessAttacks.FIN_URG++;
        writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with FIN ` +
            `and URG flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
        SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with FIN ` +
            `and URG flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if (tcpFlags == attackSigns['SYN-URG'].tcpFlags) {
        pktCounts.statelessAttacks.SYN_URG++;
        writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with SYN ` +
            `and URG flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
        SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with SYN ` +
            `and URG flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if (tcpFlags == attackSigns['SYN-FIN-URG'].tcpFlags) {
        pktCounts.statelessAttacks.SYN_FIN_URG++;
        writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with RST ` +
            `and URG flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
        SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with RST ` +
            `and URG flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if (tcpFlags == attackSigns['XMAS Scan'].tcpFlags) {
        pktCounts.statelessAttacks.XMASScan++;
        writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with FIN, ` +
            `PSH and URG flags set [X-MAS Tree Scan] to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
        SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with FIN, ` +
            `PSH and URG flags set [X-MAS Tree Scan] to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if (tcpFlags == attackSigns['SYN-FIN-PSH-URG'].tcpFlags) {
        pktCounts.statelessAttacks.SYN_FIN_PSH_URG++;
        writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with SYN, ` +
            `FIN, PSH and URG flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
        SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with SYN, ` +
            `FIN, PSH and URG flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if (tcpFlags == attackSigns['SYN-ECE-CWR'].tcpFlags) {
        pktCounts.statelessAttacks.SYN_ECE_CWR++;
        writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with SYN, ` +
            `ECN and CWR flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
        SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with SYN, ` +
            `ECN and CWR flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if ((ipFlag_DF == attackSigns['ACK-DF-WS1024'].ipFlag_DF) && 
            (tcpFlags == attackSigns['ACK-DF-WS1024'].tcpFlags) && 
            (windowSize == attackSigns['ACK-DF-WS1024'].windowSize)) {
        pktCounts.statelessAttacks.ACK_DF_WS1024++;
        writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP ACK packet with ` +
            `IP DF and a window size of 1024 to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
        SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP ACK packet with ` +
            `IP DF and a window size of 1024 to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else { }

    /* Check for Statefull Attacks */
    
    if (!attackers.has(sourceIP)) {
        let attackerState = {
            // attackerIP: sourceIP,
            pktCounts: 0,
            tcpConnections: [],
            tcpConnectionsTotal: 0,
            // tcpConnectionsIndex: 0,
            pktCounts_SYNARST: 0,
            // udpConnections: [],
            // udpConnectionsTotal: 0,
            // udpConnectionsIndex: 0,
            allPortsScan: false,
            tcp_SYNARST: false
        };
        attackers.set(sourceIP, attackerState);
    } 
    
    // Get current state of attacker
    let attacker = attackers.get(sourceIP);
    attacker.pktCounts++;
    
    // Retrieving index of connection, if a TCP connection already exists
    let tcpConn_ix = attacker.tcpConnections.findIndex(item => {
        return (item.srcPort == sourcePort && item.dstPort == destinationPort)
    });
    
    // New Connection, First Packet
    if (tcpConn_ix == -1) {
        if (tcpFlags == 2) { // SYN Packet trying to establish connection
            let newTCPConn = {
                dstIP: destinationIP,
                srcPort: sourcePort,
                dstPort: destinationPort,
                flags: {
                    SYN: true,
                    ACK: false,
                    FIN: false,
                    RST: false,
                },
                pktCounts_SYN: 1,
                timestamp: pktTimestamp,
                portScan: false,
                halfOpenScan: false
            }
            attacker.tcpConnections.push(newTCPConn);
            attacker.tcpConnectionsTotal++; 
            // attacker.tcpConnectionsIndex++;
        } else if (tcpFlags == attackSigns['FIN Scan'].tcpFlags) {
            pktCounts.statefullAttacks.FINScan++;
        } else {
            pktCounts.statefullAttacks.noSession++;
            writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet (Flags: ` + 
                `${tcpFlags}) to ${destinationIP}:${destinationPort} with no established connection. Suspecting OSFP.\n`);
            SFALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet (Flags: ` + 
                `${tcpFlags}) to ${destinationIP}:${destinationPort} with no established connection. Suspecting OSFP.\n`;
            // return;
        }
    } else { // Connection already exists (Established Connection)
        if (tcpFlags == 2) { // SYN Packet
            attacker.tcpConnections[tcpConn_ix].pktCounts_SYN++;
        } else if (tcpFlags == 16) { // ACK Packet
            attacker.tcpConnections[tcpConn_ix].flags.ACK = true;
        } else if (tcpFlags == 4) { // RST Packet 
            attacker.tcpConnections[tcpConn_ix].flags.RST = true;
            if (attacker.tcpConnections[tcpConn_ix].flags.SYN && 
                !(attacker.tcpConnections[tcpConn_ix].flags.ACK)) {
                attacker.pktCounts_SYNARST++;
            }
        } else if (tcpFlags == 1) { // FIN Packet
            attacker.tcpConnections[tcpConn_ix].flags.FIN = true;
        }
    }

    /* Check for received TCP Options */
    let tcpOpts_MSS = tcpPacket.options.mss;
    let tcpOpts_WinScale = tcpPacket.options.window_scale;
    let tcpOpts_SACK_OK = tcpPacket.options.sack_ok;
    let tcpOpts_TS_Sender = tcpPacket.options.timestamp;
    let tcpOpts_TS_Echo = tcpPacket.options.tcpOpts_TS_Echo;

    if (tcpOpts_WinScale == 10 && tcpOpts_MSS == 1460 && tcpOpts_SACK_OK 
        && tcpOpts_TS_Sender == 0xFFFFFFFF && tcpOpts_TS_Echo == 0 && windowSize == 1) {
            writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sending strange TCP options ` +
                `combination (WS: ${tcpOpts_WinScale}, MSS: ${tcpOpts_MSS}, SACK_OK: ${tcpOpts_SACK_OK}, ` +
                `Timestamp (Sender): ${tcpOpts_TS_Sender}, Timestamp (Echo): ${tcpOpts_TS_Echo}, ` +
                `Window Size: ${windowSize})}) to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
            SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sending strange TCP options ` +
                `combination (WS: ${tcpOpts_WinScale}, MSS: ${tcpOpts_MSS}, SACK_OK: ${tcpOpts_SACK_OK}, ` +
                `Timestamp (Sender): ${tcpOpts_TS_Sender}, Timestamp (Echo): ${tcpOpts_TS_Echo}, ` +
                `Window Size: ${windowSize})}) to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
    }

    if (tcpOpts_WinScale == 0 && tcpOpts_MSS == 1400 && tcpOpts_SACK_OK 
        && tcpOpts_TS_Sender == 0xFFFFFFFF && tcpOpts_TS_Echo == 0 && windowSize == 63) {
            writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sending strange TCP options ` +
                `combination (WS: ${tcpOpts_WinScale}, MSS: ${tcpOpts_MSS}, SACK_OK: ${tcpOpts_SACK_OK}, ` +
                `Timestamp (Sender): ${tcpOpts_TS_Sender}, Timestamp (Echo): ${tcpOpts_TS_Echo}, ` +
                `Window Size: ${windowSize})}) to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
            SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sending strange TCP options ` +
                `combination (WS: ${tcpOpts_WinScale}, MSS: ${tcpOpts_MSS}, SACK_OK: ${tcpOpts_SACK_OK}, ` +
                `Timestamp (Sender): ${tcpOpts_TS_Sender}, Timestamp (Echo): ${tcpOpts_TS_Echo}, ` +
                `Window Size: ${windowSize})}) to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
    }

    if (tcpOpts_WinScale == 5 && tcpOpts_MSS == 640
        && tcpOpts_TS_Sender == 0xFFFFFFFF && tcpOpts_TS_Echo == 0 && windowSize == 4) {
            writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sending strange TCP options ` + 
                `combination (WS: ${tcpOpts_WinScale}, MSS: ${tcpOpts_MSS}, Timestamp (Sender): ` +
                `${tcpOpts_TS_Sender}, Timestamp (Echo): ${tcpOpts_TS_Echo}, Window Size: ${windowSize})}) ` + 
                `to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
            SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sending strange TCP options ` + 
                `combination (WS: ${tcpOpts_WinScale}, MSS: ${tcpOpts_MSS}, Timestamp (Sender): ` +
                `${tcpOpts_TS_Sender}, Timestamp (Echo): ${tcpOpts_TS_Echo}, Window Size: ${windowSize})}) ` + 
                `to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
    }

    if (tcpOpts_WinScale == 10 && tcpOpts_SACK_OK 
        && tcpOpts_TS_Sender == 0xFFFFFFFF && tcpOpts_TS_Echo == 0 && windowSize == 4) {
            writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sending strange TCP options ` +
                `combination (WS: ${tcpOpts_WinScale}, SACK_OK: ${tcpOpts_SACK_OK}, ` +
                `Timestamp (Sender): ${tcpOpts_TS_Sender}, Timestamp (Echo): ${tcpOpts_TS_Echo}, ` +
                `Window Size: ${windowSize})}) to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
            SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sending strange TCP options ` +
                `combination (WS: ${tcpOpts_WinScale}, SACK_OK: ${tcpOpts_SACK_OK}, ` +
                `Timestamp (Sender): ${tcpOpts_TS_Sender}, Timestamp (Echo): ${tcpOpts_TS_Echo}, ` +
                `Window Size: ${windowSize})}) to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
    }

    if (tcpOpts_WinScale == 10 && tcpOpts_MSS == 536 && tcpOpts_SACK_OK 
        && tcpOpts_TS_Sender == 0xFFFFFFFF && tcpOpts_TS_Echo == 0 && windowSize == 16) {
            writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sending strange TCP options ` +
                `combination (WS: ${tcpOpts_WinScale}, MSS: ${tcpOpts_MSS}, SACK_OK: ${tcpOpts_SACK_OK}, ` +
                `Timestamp (Sender): ${tcpOpts_TS_Sender}, Timestamp (Echo): ${tcpOpts_TS_Echo}, ` +
                `Window Size: ${windowSize})}) to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
            SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sending strange TCP options ` +
                `combination (WS: ${tcpOpts_WinScale}, MSS: ${tcpOpts_MSS}, SACK_OK: ${tcpOpts_SACK_OK}, ` +
                `Timestamp (Sender): ${tcpOpts_TS_Sender}, Timestamp (Echo): ${tcpOpts_TS_Echo}, ` +
                `Window Size: ${windowSize})}) to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
    }

    if (tcpOpts_MSS == 256 && tcpOpts_SACK_OK 
        && tcpOpts_TS_Sender == 0xFFFFFFFF && tcpOpts_TS_Echo == 0 && windowSize == 512) {
            writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sending strange TCP options ` +
                `combination (MSS: ${tcpOpts_MSS}, SACK_OK: ${tcpOpts_SACK_OK}, ` + 
                `Timestamp (Sender): ${tcpOpts_TS_Sender}, Timestamp (Echo): ${tcpOpts_TS_Echo}, ` +
                `Window Size: ${windowSize})}) to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`);
            SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sending strange TCP options ` +
                `combination (MSS: ${tcpOpts_MSS}, SACK_OK: ${tcpOpts_SACK_OK}, ` + 
                `Timestamp (Sender): ${tcpOpts_TS_Sender}, Timestamp (Echo): ${tcpOpts_TS_Echo}, ` +
                `Window Size: ${windowSize})}) to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
    }

    // Updating attacker's state
    attackers.set(sourceIP, attacker);
}

function parseICMP(ipPacket, pktTimestamp) {

    // Extracting Source & Destination IP
    let sourceIP = ipPacket.saddr['addr'].join('.');
    let destinationIP = ipPacket.daddr['addr'].join('.');
    
    let icmpPacket = ipPacket.payload;
    // Extracting ICMP Type and ICMP Code
    let icmpType = icmpPacket.type;
    let icmpCode = icmpPacket.code;

    if (icmpType == attackSigns['Invalid Code'].type && icmpCode > attackSigns['Invalid Code'].codeGT) {
        pktCounts.icmpAttacks.invalidCode++;
        writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a ICMP packet with invalid ` +
            `Code value to ${destinationIP}. Suspecting OSFP.\n`);
        SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a ICMP packet with invalid ` +
            `Code value to ${destinationIP}. Suspecting OSFP.\n`;
    } else if (icmpType in attackSigns['Invalid Type'].typeIN || icmpType >= attackSigns['Invalid Type'].typeGTE) {
        pktCounts.icmpAttacks.invalidType++;
        writeStream.write(`[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a ICMP packet with reserved ` +
            `Type value to ${destinationIP}. Suspecting OSFP.\n`);
        SLALogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a ICMP packet with reserved ` +
            `Type value to ${destinationIP}. Suspecting OSFP.\n`;
    }
}

function forkAnalysis(attackers) {
    const analysisProcess = fork('../common/attackersAnalysis.js');
    
    // console.log(`\nSent ${attackers.size} potential attackers for analysis.`);
    let data = JSON.stringify([...attackers]);
    analysisProcess.send(data);

    analysisProcess.on('message', (results) => {
        writeStream.write(results);
        SFALogs += results;
        analysisProcess.kill();
    });
}

process.on('message', (args) => {
    if (args == 'start') {
        getSignatures().then(() => {
            const MY_IP = '10.13.200.148';
            const HOST_IP = '10.15.4.110';
            // Filter for packets sent to my systen
            newSession = pcap.createSession('', `src host ${MY_IP}`);
            // No filter
            // newSession = pcap.createSession('');
            console.log(`Sniffing started on ${newSession.device_name}`);
            attackers = new Map();
            let curTimestamp = new Date();
            logFile = `logFile${curTimestamp.valueOf()}.log`;
            writeStream = fs.createWriteStream(`${__dirname}/logs/${logFile}`);
            console.log(`Writing to ${__dirname}/logs/${logFile}.`);
            process.send(`Sniffing started on ${newSession.device_name}`);
            newSession.on('packet', parsePacket);
            setInterval(forkAnalysis, 60000, attackers);
        });
    } else if (args == 'getLogs:StatelessAttack') {
        if (SLALogs.length == 0) { 
            console.log('No logs (SLA) yet!');
	        process.send('');
        } else { 
	        process.send(SLALogs);
            SLALogs = '';
	    }
    } else if (args == 'getLogs:StatefullAttack') {
        if (SFALogs.length == 0) { 
            console.log('No logs (SFA) yet!');
	        process.send('');
        } else { 
	        process.send(SFALogs);
            SFALogs = '';
	    }
    } else if (args == 'stop') {
        newSession.close();
        console.log(`Sniffing session on ${newSession.device_name} closed. Sniffed ${pktCounts.totalPkts} packets.`);
        writeStream.on('finish', () => {
            console.log(`Wrote all data to ${logFile}!`);
        });
        writeStream.end();
        process.send({ status: `Sniffing session on ${newSession.device_name} closed. Sniffed ${pktCounts.totalPkts} packets.`, pktCounts, SLALogs, SFALogs });
    }
});
