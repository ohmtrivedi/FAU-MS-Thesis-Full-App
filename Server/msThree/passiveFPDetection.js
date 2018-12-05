'use strict'

const pcapp = require('pcap-parser'),
    { fork } = require('child_process'),
    { MongoClient } = require('mongodb'),
    { USERNAME, PASSWORD, SERVER_URL, DATABASE } = require('../common/mongoDBConfig');

let attackSigns, pcapParser, attackers;
let consoleLogs = '';
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
            
            let query = { };

            mydb.collection('attackSigns')
            .find(query, { projection: { _id: 0, attack: 1, sign: 1 } })
            .toArray((err, result) => {
                if (err) reject(err);
                attackSigns = result.reduce((map, obj) => {
                    map[obj.attack] = obj.sign;
                    return map;
                }, {});
                resolve(attackSigns);
                db.close();
            });
        });
    });
}

function parsePacket(packet) {
    let packetHeader = packet.header;
    let packetContent = packet.data;
    
    let pktTimestamp = new Date(packetHeader.timestampSeconds*1000);
    pktCounts.totalPkts++;

    // Parsing Ethernet Header...
    // Check for IPv4 (EtherType)
    if (packetContent.readUInt8(12) != 8 && packetContent.readUInt8(13) != 0) {
        // console.log('Not IPv4 Packet');
        return;
    }

    // Parsing IPv4 Header....
    // Check for IPv4 (Version 4) (Version)
    let ipv4_VHL = packetContent.readUInt8(14);
    if ( ipv4_VHL < 69 || ipv4_VHL > 79) {
        // console.log('Invalid IPv4 Packet');
        return;
    }

    // Extracting Protocol
    let protocol = packetContent.readUInt8(0x17);

    switch (protocol) {
        case 1:
            pktCounts.icmpPkts++;
            parseICMP(packetContent, pktTimestamp);
            break;
        case 6:
            pktCounts.tcpPkts++;
            parseTCP(packetContent, pktTimestamp);
            break;
        case 17:
            pktCounts.udpPkts++;
            break;
        default:
            // console.log('Unknown Protocol');
            break;
    }
}

function parseTCP(packetContent, pktTimestamp) {
    // Extracting Fragmentation Info
    let dfFlag = packetContent.readUInt16LE(0x14);

    // Extracting Source & Destination IP
    let sourceIP = packetContent.readUInt8(0x1A).toString() + '.' +
        packetContent.readUInt8(0x1B).toString() + '.' +
        packetContent.readUInt8(0x1C).toString() + '.' +
        packetContent.readUInt8(0x1D).toString();

    let destinationIP = packetContent.readUInt8(0x1E).toString() + '.' +
        packetContent.readUInt8(0x1F).toString() + '.' +
        packetContent.readUInt8(0x20).toString() + '.' +
        packetContent.readUInt8(0x21).toString();

    // Parsing TCP Header...
    // Extracting Source & Destination Port
    let sourcePort = packetContent.readUInt16BE(0x22);
    let destinationPort = packetContent.readUInt16BE(0x24);
    // Extracting Window Size
    let windowSize = packetContent.readUInt16BE(0x30);

    /* Check for Stateless Attacks */

    if (packetContent.readUInt8(0x2F) == attackSigns['Null Scan'].tcpFlags) {
        pktCounts.statelessAttacks.NULLScan++;
        consoleLogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with no flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if ((packetContent.readUInt8(0x2F) & 3) == attackSigns['SYN-FIN'].tcpFlags) {
        pktCounts.statelessAttacks.SYN_FIN++;
        consoleLogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with SYN and FIN flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if ((packetContent.readUInt8(0x2F) & 5) == attackSigns['RST-FIN'].tcpFlags) {
        pktCounts.statelessAttacks.RST_FIN++;
        consoleLogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with RST and FIN flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if ((packetContent.readUInt8(0x2F) & 6) == attackSigns['RST-SYN'].tcpFlags) {
        pktCounts.statelessAttacks.RST_SYN++;
        consoleLogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with RST and SYN flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if ((packetContent.readUInt8(0x2F) & 8) == attackSigns['PSH'].tcpFlags) {
        pktCounts.statelessAttacks.PSH++;
        consoleLogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet containing only PSH flag to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if ((packetContent.readUInt8(0x2F) & 18) == 18) {
        // pktCounts.SYN_ACK++;
        return;
    } else if ((packetContent.readUInt8(0x2F) & 33) == attackSigns['FIN-URG'].tcpFlags) {
        pktCounts.statelessAttacks.FIN_URG++;
        consoleLogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with FIN and URG flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if ((packetContent.readUInt8(0x2F) & 34) == attackSigns['SYN-URG'].tcpFlags) {
        pktCounts.statelessAttacks.SYN_URG++;
        consoleLogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with SYN and URG flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if ((packetContent.readUInt8(0x2F) & 36) == attackSigns['SYN-FIN-URG'].tcpFlags) {
        pktCounts.statelessAttacks.SYN_FIN_URG++;
        consoleLogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with RST and URG flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if ((packetContent.readUInt8(0x2F) & 41) == attackSigns['XMAS Scan'].tcpFlags) {
        pktCounts.statelessAttacks.XMASScan++;
        consoleLogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with FIN, PSH and URG flags set [X-MAS Tree Scan] to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if ((packetContent.readUInt8(0x2F) & 43) == attackSigns['SYN-FIN-PSH-URG'].tcpFlags) {
        pktCounts.statelessAttacks.SYN_FIN_PSH_URG++;
        consoleLogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with SYN, FIN, PSH and URG flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if ((packetContent.readUInt8(0x2F) & 194) == attackSigns['SYN-ECE-CWR'].tcpFlags) {
        pktCounts.statelessAttacks.SYN_ECE_CWR++;
        consoleLogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet with SYN, ECN and CWR flags set to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
        return;
    } else if ((dfFlag == attackSigns['ACK-DF-WS1024'].ipFlag_DF) && 
            ((packetContent.readUInt8(0x2F) & 16) == attackSigns['ACK-DF-WS1024'].tcpFlags) && 
            (windowSize == attackSigns['ACK-DF-WS1024'].windowSize)) {
        pktCounts.statelessAttacks.ACK_DF_WS1024++;
        consoleLogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP ACK packet with IP DF and a window size of 1024 to ${destinationIP}:${destinationPort}. Suspecting OSFP.\n`;
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
    
    let tcpFlags = packetContent.readUInt8(0x2F);
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
            consoleLogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a TCP packet (Flags: ${tcpFlags}) to ${destinationIP}:${destinationPort} with no established connection. Suspecting OSFP.\n`;
            // return;
        }
    } else { // Connection already exists (Established Connection)
        if (tcpFlags == 2) { // SYN Packet
            attacker.tcpConnections[tcpConn_ix].pktCounts_SYN++;
        } else if (tcpFlags == 16) { // ACK Packet
            attacker.tcpConnections[tcpConn_ix].flags.ACK = true;
        } else if (tcpFlags == 4) { // RST Packet 
            attacker.tcpConnections[tcpConn_ix].flags.RST = true;
            if (attacker.tcpConnections[tcpConn_ix].flags.SYN && !(attacker.tcpConnections[tcpConn_ix].flags.ACK)) {
                attacker.pktCounts_SYNARST++;
            }
        } else if (tcpFlags == 1) { // FIN Packet
            attacker.tcpConnections[tcpConn_ix].flags.FIN = true;
        }
    }

    /* TODO: Check for received TCP Options 
        Comment: Cannot be done, difficult to retrieve individual options because of NOP complication */
    let tcpOptionsIx = 0x36;

    // Updating attacker's state
    attackers.set(sourceIP, attacker);
}

function parseICMP(packetContent, pktTimestamp) {

    // Extracting Source & Destination IP
    let sourceIP = packetContent.readUInt8(0x1A).toString() + '.' +
        packetContent.readUInt8(0x1B).toString() + '.' +
        packetContent.readUInt8(0x1C).toString() + '.' +
        packetContent.readUInt8(0x1D).toString();

    let destinationIP = packetContent.readUInt8(0x1E).toString() + '.' +
        packetContent.readUInt8(0x1F).toString() + '.' +
        packetContent.readUInt8(0x20).toString() + '.' +
        packetContent.readUInt8(0x21).toString();
    
    // Extracting ICMP Type and ICMP Code
    let icmpType = packetContent.readUInt8(0x22);
    let icmpCode = packetContent.readUInt8(0x23);

    if (icmpType == attackSigns['Invalid Code'].type && icmpCode > attackSigns['Invalid Code'].codeGT) {
        pktCounts.icmpAttacks.invalidCode++;
        consoleLogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a ICMP packet with invalid code value to ${destinationIP}. Suspecting OSFP.\n`;
    } else if (icmpType in attackSigns['Invalid Type'].typeIN || icmpType >= attackSigns['Invalid Type'].typeGTE) {
        pktCounts.icmpAttacks.invalidType++;
        consoleLogs += `[${pktTimestamp.toLocaleString()}] ${sourceIP} sent a ICMP packet with reserved type value to ${destinationIP}. Suspecting OSFP.\n`;
    }
}

function forkAnalysis(attackers) {
    const analysisProcess = fork('../common/attackersAnalysis.js');
    
    // console.log(`Sent ${attackers.size} potential attackers for analysis.`);
    let data = JSON.stringify([...attackers]);
    analysisProcess.send(data);

    return new Promise((resolve, reject) => {
        analysisProcess.on('message', (results) => {
            resolve(results);
            analysisProcess.kill();
        });
    });
}

process.on('message', (filePath) => {
    getSignatures().then(() => {
        pcapParser = pcapp.parse(filePath);
        attackers = new Map();

        pcapParser.on('packet', (packet) => {
            parsePacket(packet);
        });

        pcapParser.on('end', () => {
            forkAnalysis(attackers).then((analysisResults) => {
                // console.log(analysisResults);
                console.log(`Analyzed ${pktCounts.totalPkts} packets.`);
                process.send({ pktCounts, consoleLogs, analysisResults });
            });
        });

        pcapParser.on('error', (error) => {
            console.log(error);
        });
    });
});
