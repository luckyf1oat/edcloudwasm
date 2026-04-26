import {connect} from 'cloudflare:sockets';
const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';//vless使用的uuid
//**警告**:trojan使用的sha224密钥，需要自己计算，当前设置为密码666的密钥
//**警告**:trojan使用的sha224密钥，需要自己计算，当前设置为密码666的密钥
//**警告**:trojan使用的sha224密钥，需要自己计算，当前设置为密码666的密钥
//**警告**:trojan使用的sha224密钥计算网址：https://www.lzltool.com/data-sha224
const passWordSha224 = '509eece82eb6910bebef9af9496092d3244b6c0d69ef3aaa4b12c565';
const bufferSize = 512 * 1024;
const startThreshold = 50 * 1024 * 1024;
const maxChunkLen = 64 * 1024;
const flushTime = 20;
const proxyStrategyOrder = ['socks', 'http'];
const proxyIpAddrs = {EU: 'ProxyIP.DE.CMLiussss.net', AS: 'ProxyIP.SG.CMLiussss.net', JP: 'ProxyIP.JP.CMLiussss.net', US: 'ProxyIP.US.CMLiussss.net'};//分区域proxyip
const coloRegions = {
    JP: new Set(['FUK', 'ICN', 'KIX', 'NRT', 'OKA']),
    EU: new Set([
        'ACC', 'ADB', 'ALA', 'ALG', 'AMM', 'AMS', 'ARN', 'ATH', 'BAH', 'BCN', 'BEG', 'BGW', 'BOD', 'BRU', 'BTS', 'BUD', 'CAI',
        'CDG', 'CPH', 'CPT', 'DAR', 'DKR', 'DMM', 'DOH', 'DUB', 'DUR', 'DUS', 'DXB', 'EBB', 'EDI', 'EVN', 'FCO', 'FRA', 'GOT',
        'GVA', 'HAM', 'HEL', 'HRE', 'IST', 'JED', 'JIB', 'JNB', 'KBP', 'KEF', 'KWI', 'LAD', 'LED', 'LHR', 'LIS', 'LOS', 'LUX',
        'LYS', 'MAD', 'MAN', 'MCT', 'MPM', 'MRS', 'MUC', 'MXP', 'NBO', 'OSL', 'OTP', 'PMO', 'PRG', 'RIX', 'RUH', 'RUN', 'SKG',
        'SOF', 'STR', 'TBS', 'TLL', 'TLV', 'TUN', 'VIE', 'VNO', 'WAW', 'ZAG', 'ZRH']),
    AS: new Set([
        'ADL', 'AKL', 'AMD', 'BKK', 'BLR', 'BNE', 'BOM', 'CBR', 'CCU', 'CEB', 'CGK', 'CMB', 'COK', 'DAC', 'DEL', 'HAN', 'HKG',
        'HYD', 'ISB', 'JHB', 'JOG', 'KCH', 'KHH', 'KHI', 'KTM', 'KUL', 'LHE', 'MAA', 'MEL', 'MFM', 'MLE', 'MNL', 'NAG', 'NOU',
        'PAT', 'PBH', 'PER', 'PNH', 'SGN', 'SIN', 'SYD', 'TPE', 'ULN', 'VTE'])
};
const coloToProxyMap = new Map();
for (const [region, colos] of Object.entries(coloRegions)) {for (const colo of colos) coloToProxyMap.set(colo, proxyIpAddrs[region])}
const uuidBytes = new Uint8Array(16), hashBytes = new Uint8Array(56), offsets = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 4, 4, 4, 4];
for (let i = 0, c; i < 16; i++) uuidBytes[i] = (((c = uuid.charCodeAt(i * 2 + offsets[i])) > 64 ? c + 9 : c) & 0xF) << 4 | (((c = uuid.charCodeAt(i * 2 + offsets[i] + 1)) > 64 ? c + 9 : c) & 0xF);
for (let i = 0; i < 56; i++) hashBytes[i] = passWordSha224.charCodeAt(i);
const [textEncoder, textDecoder, socks5Init] = [new TextEncoder(), new TextDecoder(), new Uint8Array([5, 2, 0, 2])];
const ssCipherConfigs = {
    'aes-128-gcm': {
        keyLen: 16,
        saltLen: 16,
        aesLength: 128,
        maxChunk: 0x3FFF
    }
};
const ssAeadTagLen = 16;
const ssNonceLen = 12;
const ssSubKeyInfo = textEncoder.encode('ss-subkey');
const ssMasterKeyCache = new Map();
const html = `<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.25.3</center></body></html>`;
const binaryAddrToString = (addrType, addrBytes) => {
    if (addrType === 3) return textDecoder.decode(addrBytes);
    if (addrType === 1) return `${addrBytes[0]}.${addrBytes[1]}.${addrBytes[2]}.${addrBytes[3]}`;
    let ipv6 = ((addrBytes[0] << 8) | addrBytes[1]).toString(16);
    for (let i = 1; i < 8; i++) ipv6 += ':' + ((addrBytes[i * 2] << 8) | addrBytes[i * 2 + 1]).toString(16);
    return `[${ipv6}]`;
};
const parseHostPort = (addr, defaultPort) => {
    let host = addr, port = defaultPort, idx;
    if (addr.charCodeAt(0) === 91) {
        if ((idx = addr.indexOf(']:')) !== -1) {
            host = addr.substring(0, idx + 1);
            port = addr.substring(idx + 2);
        }
    } else if ((idx = addr.indexOf('.tp')) !== -1 && addr.lastIndexOf(':') === -1) {
        port = addr.substring(idx + 3, addr.indexOf('.', idx + 3));
    } else if ((idx = addr.lastIndexOf(':')) !== -1) {
        host = addr.substring(0, idx);
        port = addr.substring(idx + 1);
    }
    return [host, (port = parseInt(port), isNaN(port) ? defaultPort : port)];
};
const parseAuthString = (authParam) => {
    let username, password, hostStr;
    const atIndex = authParam.lastIndexOf('@');
    if (atIndex === -1) {hostStr = authParam} else {
        const cred = authParam.substring(0, atIndex);
        hostStr = authParam.substring(atIndex + 1);
        const colonIndex = cred.indexOf(':');
        if (colonIndex === -1) {username = cred} else {
            username = cred.substring(0, colonIndex);
            password = cred.substring(colonIndex + 1);
        }
    }
    const [hostname, port] = parseHostPort(hostStr, 1080);
    return {username, password, hostname, port};
};
const createConnect = (hostname, port, socket = connect({hostname, port})) => socket.opened.then(() => socket);
const connectViaSocksProxy = async (targetAddrType, targetPortNum, socksAuth, addrBytes) => {
    const socksSocket = await createConnect(socksAuth.hostname, socksAuth.port);
    const writer = socksSocket.writable.getWriter();
    const reader = socksSocket.readable.getReader();
    await writer.write(socks5Init);
    const {value: authResponse} = await reader.read();
    if (!authResponse || authResponse[0] !== 5 || authResponse[1] === 0xFF) return null;
    if (authResponse[1] === 2) {
        if (!socksAuth.username) return null;
        const userBytes = textEncoder.encode(socksAuth.username);
        const passBytes = textEncoder.encode(socksAuth.password || '');
        const uLen = userBytes.length, pLen = passBytes.length, authReq = new Uint8Array(3 + uLen + pLen)
        authReq[0] = 1, authReq[1] = uLen, authReq.set(userBytes, 2), authReq[2 + uLen] = pLen, authReq.set(passBytes, 3 + uLen);
        await writer.write(authReq);
        const {value: authResult} = await reader.read();
        if (!authResult || authResult[0] !== 1 || authResult[1] !== 0) return null;
    } else if (authResponse[1] !== 0) {return null}
    const isDomain = targetAddrType === 3, socksReq = new Uint8Array(6 + addrBytes.length + (isDomain ? 1 : 0));
    socksReq[0] = 5, socksReq[1] = 1, socksReq[2] = 0, socksReq[3] = targetAddrType;
    isDomain ? (socksReq[4] = addrBytes.length, socksReq.set(addrBytes, 5)) : socksReq.set(addrBytes, 4);
    socksReq[socksReq.length - 2] = targetPortNum >> 8, socksReq[socksReq.length - 1] = targetPortNum & 0xff;
    await writer.write(socksReq);
    const {value: finalResponse} = await reader.read();
    if (!finalResponse || finalResponse[1] !== 0) return null;
    writer.releaseLock(), reader.releaseLock();
    return socksSocket;
};
const staticHeaders = `User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n`;
const encodedStaticHeaders = textEncoder.encode(staticHeaders);
const connectViaHttpProxy = async (targetAddrType, targetPortNum, httpAuth, addrBytes) => {
    const {username, password, hostname, port} = httpAuth;
    const proxySocket = await createConnect(hostname, port);
    const writer = proxySocket.writable.getWriter();
    const httpHost = binaryAddrToString(targetAddrType, addrBytes);
    let dynamicHeaders = `CONNECT ${httpHost}:${targetPortNum} HTTP/1.1\r\nHost: ${httpHost}:${targetPortNum}\r\n`;
    if (username) dynamicHeaders += `Proxy-Authorization: Basic ${btoa(`${username}:${password || ''}`)}\r\n`;
    const fullHeaders = new Uint8Array(dynamicHeaders.length * 3 + encodedStaticHeaders.length);
    const {written} = textEncoder.encodeInto(dynamicHeaders, fullHeaders);
    fullHeaders.set(encodedStaticHeaders, written);
    await writer.write(fullHeaders.subarray(0, written + encodedStaticHeaders.length));
    writer.releaseLock();
    const reader = proxySocket.readable.getReader();
    const buffer = new Uint8Array(512);
    let bytesRead = 0, statusChecked = false;
    while (bytesRead < buffer.length) {
        const {value, done} = await reader.read();
        if (done || bytesRead + value.length > buffer.length) return null;
        const prevBytesRead = bytesRead;
        buffer.set(value, bytesRead);
        bytesRead += value.length;
        if (!statusChecked && bytesRead >= 12) {
            if (buffer[9] !== 50) return null;
            statusChecked = true;
        }
        let i = Math.max(15, prevBytesRead - 3);
        while ((i = buffer.indexOf(13, i)) !== -1 && i <= bytesRead - 4) {
            if (buffer[i + 1] === 10 && buffer[i + 2] === 13 && buffer[i + 3] === 10) {
                reader.releaseLock();
                return proxySocket;
            }
            i++;
        }
    }
    return null;
};
const parseAddress = (buffer, offset, addrType) => {
    const addressLength = addrType === 3 ? buffer[offset++] : addrType === 1 ? 4 : addrType === 4 ? 16 : null;
    if (addressLength === null) return null;
    const dataOffset = offset + addressLength;
    if (dataOffset > buffer.length) return null;
    const addrBytes = buffer.subarray(offset, dataOffset);
    return {addrBytes, dataOffset};
};
const ssToUint8 = (data) => {
    if (!data) return new Uint8Array(0);
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    return new Uint8Array(data);
};
const ssConcat = (...chunkList) => {
    if (!chunkList || chunkList.length === 0) return new Uint8Array(0);
    const chunks = chunkList.map(ssToUint8);
    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
    if (totalLength === 0) return new Uint8Array(0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (let i = 0; i < chunks.length; i++) {
        result.set(chunks[i], offset);
        offset += chunks[i].byteLength;
    }
    return result;
};
const ssIncNonce = (counter) => {
    for (let i = 0; i < counter.length; i++) {
        counter[i] = (counter[i] + 1) & 0xff;
        if (counter[i] !== 0) break;
    }
};
const ssDeriveMasterKey = async (passwordText, keyLen) => {
    const cacheKey = `${keyLen}:${passwordText}`;
    if (ssMasterKeyCache.has(cacheKey)) return ssMasterKeyCache.get(cacheKey);
    const deriveTask = (async () => {
        const passwordBytes = textEncoder.encode(passwordText || '');
        let previous = new Uint8Array(0), result = new Uint8Array(0);
        while (result.byteLength < keyLen) {
            const input = new Uint8Array(previous.byteLength + passwordBytes.byteLength);
            input.set(previous, 0), input.set(passwordBytes, previous.byteLength);
            previous = new Uint8Array(await crypto.subtle.digest('MD5', input));
            result = ssConcat(result, previous);
        }
        return result.subarray(0, keyLen);
    })();
    ssMasterKeyCache.set(cacheKey, deriveTask);
    try {
        return await deriveTask;
    } catch (error) {
        ssMasterKeyCache.delete(cacheKey);
        throw error;
    }
};
const ssDeriveSessionKey = async (config, masterKey, salt, usages) => {
    const saltHmacKey = await crypto.subtle.importKey('raw', salt, {name: 'HMAC', hash: 'SHA-1'}, false, ['sign']);
    const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltHmacKey, masterKey));
    const prkHmacKey = await crypto.subtle.importKey('raw', prk, {name: 'HMAC', hash: 'SHA-1'}, false, ['sign']);
    const subKey = new Uint8Array(config.keyLen);
    let previous = new Uint8Array(0), written = 0, counter = 1;
    while (written < config.keyLen) {
        const input = ssConcat(previous, ssSubKeyInfo, new Uint8Array([counter]));
        previous = new Uint8Array(await crypto.subtle.sign('HMAC', prkHmacKey, input));
        const copyLength = Math.min(previous.byteLength, config.keyLen - written);
        subKey.set(previous.subarray(0, copyLength), written);
        written += copyLength, counter++;
    }
    return crypto.subtle.importKey('raw', subKey, {name: 'AES-GCM', length: config.aesLength}, false, usages);
};
const ssAeadEncrypt = async (cryptoKey, nonceCounter, plaintext) => {
    const iv = nonceCounter.slice();
    const ciphertext = await crypto.subtle.encrypt({name: 'AES-GCM', iv, tagLength: 128}, cryptoKey, plaintext);
    ssIncNonce(nonceCounter);
    return new Uint8Array(ciphertext);
};
const ssAeadDecrypt = async (cryptoKey, nonceCounter, ciphertext) => {
    const iv = nonceCounter.slice();
    const plaintext = await crypto.subtle.decrypt({name: 'AES-GCM', iv, tagLength: 128}, cryptoKey, ciphertext);
    ssIncNonce(nonceCounter);
    return new Uint8Array(plaintext);
};
const createSsInboundDecryptor = (config, passwordText) => {
    const inboundState = {
        hasSalt: false,
        decryptKey: null,
        nonceCounter: new Uint8Array(ssNonceLen),
        waitPayloadLength: null,
        buffer: new Uint8Array(0)
    };
    return {
        async input(dataChunk) {
            const chunk = ssToUint8(dataChunk);
            if (chunk.byteLength > 0) inboundState.buffer = ssConcat(inboundState.buffer, chunk);
            const plaintextChunks = [];
            if (!inboundState.hasSalt) {
                if (inboundState.buffer.byteLength < config.saltLen) return plaintextChunks;
                const salt = inboundState.buffer.subarray(0, config.saltLen);
                inboundState.buffer = inboundState.buffer.subarray(config.saltLen);
                const masterKey = await ssDeriveMasterKey(passwordText, config.keyLen);
                inboundState.decryptKey = await ssDeriveSessionKey(config, masterKey, salt, ['decrypt']);
                inboundState.hasSalt = true;
            }
            while (true) {
                if (inboundState.waitPayloadLength === null) {
                    const lengthCipherTotalLength = 2 + ssAeadTagLen;
                    if (inboundState.buffer.byteLength < lengthCipherTotalLength) break;
                    const lengthCipher = inboundState.buffer.subarray(0, lengthCipherTotalLength);
                    inboundState.buffer = inboundState.buffer.subarray(lengthCipherTotalLength);
                    const lengthPlain = await ssAeadDecrypt(inboundState.decryptKey, inboundState.nonceCounter, lengthCipher);
                    if (lengthPlain.byteLength !== 2) throw new Error('SS length decrypt failed');
                    const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
                    if (payloadLength < 0 || payloadLength > config.maxChunk) throw new Error(`SS payload length invalid: ${payloadLength}`);
                    inboundState.waitPayloadLength = payloadLength;
                }
                const payloadCipherTotalLength = inboundState.waitPayloadLength + ssAeadTagLen;
                if (inboundState.buffer.byteLength < payloadCipherTotalLength) break;
                const payloadCipher = inboundState.buffer.subarray(0, payloadCipherTotalLength);
                inboundState.buffer = inboundState.buffer.subarray(payloadCipherTotalLength);
                const payloadPlain = await ssAeadDecrypt(inboundState.decryptKey, inboundState.nonceCounter, payloadCipher);
                inboundState.waitPayloadLength = null;
                plaintextChunks.push(payloadPlain);
            }
            return plaintextChunks;
        }
    };
};
const createSsOutboundEncryptor = async (config, passwordText) => {
    const masterKey = await ssDeriveMasterKey(passwordText, config.keyLen);
    const salt = crypto.getRandomValues(new Uint8Array(config.saltLen));
    const encryptKey = await ssDeriveSessionKey(config, masterKey, salt, ['encrypt']);
    const nonceCounter = new Uint8Array(ssNonceLen);
    let saltSent = false;
    return {
        async encrypt(dataChunk) {
            const plaintextData = ssToUint8(dataChunk);
            const outboundChunks = [];
            if (!saltSent) {
                outboundChunks.push(salt);
                saltSent = true;
            }
            if (plaintextData.byteLength === 0) return ssConcat(...outboundChunks);
            let offset = 0;
            while (offset < plaintextData.byteLength) {
                const payloadPlain = plaintextData.subarray(offset, Math.min(offset + config.maxChunk, plaintextData.byteLength));
                offset += payloadPlain.byteLength;
                const lengthPlain = new Uint8Array(2);
                lengthPlain[0] = payloadPlain.byteLength >> 8;
                lengthPlain[1] = payloadPlain.byteLength & 0xff;
                const lengthCipher = await ssAeadEncrypt(encryptKey, nonceCounter, lengthPlain);
                const payloadCipher = await ssAeadEncrypt(encryptKey, nonceCounter, payloadPlain);
                outboundChunks.push(lengthCipher, payloadCipher);
            }
            return ssConcat(...outboundChunks);
        }
    };
};
const parseRequestData = (firstChunk) => {
    for (let i = 0; i < 16; i++) if (firstChunk[i + 1] !== uuidBytes[i]) return null;
    let offset = 19 + firstChunk[17];
    const port = (firstChunk[offset] << 8) | firstChunk[offset + 1];
    let addrType = firstChunk[offset + 2];
    if (addrType !== 1) addrType += 1;
    const addrInfo = parseAddress(firstChunk, offset + 3, addrType);
    if (!addrInfo) return null;
    return {addrType, addrBytes: addrInfo.addrBytes, dataOffset: addrInfo.dataOffset, port};
};
const parseTransparent = (firstChunk) => {
    for (let i = 0; i < 56; i++) if (firstChunk[i] !== hashBytes[i]) return null;
    const addrType = firstChunk[59];
    const addrInfo = parseAddress(firstChunk, 60, addrType);
    if (!addrInfo) return null;
    const port = (firstChunk[addrInfo.dataOffset] << 8) | firstChunk[addrInfo.dataOffset + 1];
    return {addrType, addrBytes: addrInfo.addrBytes, dataOffset: addrInfo.dataOffset + 4, port};
};
const parseShadow = (firstChunk) => {
    const addrType = firstChunk[0];
    const addrInfo = parseAddress(firstChunk, 1, addrType);
    if (!addrInfo) return null;
    const port = (firstChunk[addrInfo.dataOffset] << 8) | firstChunk[addrInfo.dataOffset + 1];
    return {addrType, addrBytes: addrInfo.addrBytes, dataOffset: addrInfo.dataOffset + 2, port};
};
const strategyExecutorMap = new Map([
    [0, async ({addrType, port, addrBytes}) => {
        const hostname = binaryAddrToString(addrType, addrBytes);
        return createConnect(hostname, port);
    }],
    [1, async ({addrType, port, addrBytes}, param) => {
        const socksAuth = parseAuthString(param);
        return connectViaSocksProxy(addrType, port, socksAuth, addrBytes);
    }],
    [2, async ({addrType, port, addrBytes}, param) => {
        const httpAuth = parseAuthString(param);
        return connectViaHttpProxy(addrType, port, httpAuth, addrBytes);
    }],
    [3, async (_parsedRequest, param) => {
        const [host, port] = parseHostPort(param, 443);
        return createConnect(host, port);
    }]
]);
const paramRegex = /(gs5|s5all|ghttp|httpall|s5|socks|http|ip)(?:=|:\/\/|%3A%2F%2F)([^&]+)|(proxyall|globalproxy)/gi;
const establishTcpConnection = async (parsedRequest, request) => {
    let u = request.url, clean = u.slice(u.indexOf('/', 10) + 1), list = [];
    if (clean.length < 6) {list.push({type: 0}, {type: 3, param: coloToProxyMap.get(request.cf?.colo) ?? proxyIpAddrs.US})} else {
        paramRegex.lastIndex = 0;
        let m, p = Object.create(null);
        while ((m = paramRegex.exec(clean))) p[(m[1] || m[3]).toLowerCase()] = m[2] ? (m[2].charCodeAt(m[2].length - 1) === 61 ? m[2].slice(0, -1) : m[2]) : true;
        const s5 = p.gs5 || p.s5all || p.s5 || p.socks, http = p.ghttp || p.httpall || p.http;
        const proxyAll = !!(p.gs5 || p.s5all || p.ghttp || p.httpall || p.proxyall || p.globalproxy);
        if (!proxyAll) list.push({type: 0});
        const add = (v, t) => {
            if (!v) return;
            const parts = decodeURIComponent(v).split(',');
            for (let i = 0; i < parts.length; i++) if (parts[i]) list.push({type: t, param: parts[i]});
        };
        for (let i = 0; i < proxyStrategyOrder.length; i++) {
            const k = proxyStrategyOrder[i];
            k === 'socks' ? add(s5, 1) : k === 'http' ? add(http, 2) : 0;
        }
        if (proxyAll) {if (!list.length) list.push({type: 0})} else {
            add(p.ip, 3);
            list.push({type: 3, param: coloToProxyMap.get(request.cf?.colo) ?? proxyIpAddrs.US});
        }
    }
    for (let i = 0; i < list.length; i++) {
        try {
            const socket = await strategyExecutorMap.get(list[i].type)?.(parsedRequest, list[i].param);
            if (socket) return socket;
        } catch {}
    }
    return null;
};
const chunkIdxLookup = new Uint8Array(257);
for (let i = 0; i <= 256; i++) {
    let len = i << 8;
    if (len < 512) chunkIdxLookup[i] = 0;
    else if (len < 1024) chunkIdxLookup[i] = 1;
    else if (len < 2048) chunkIdxLookup[i] = 2;
    else if (len < 3072) chunkIdxLookup[i] = 3;
    else if (len < 4096) chunkIdxLookup[i] = 4;
    else if (len < 6144) chunkIdxLookup[i] = 5;
    else if (len < 8192) chunkIdxLookup[i] = 6;
    else if (len < 12288) chunkIdxLookup[i] = 7;
    else if (len < 20480) chunkIdxLookup[i] = 8;
    else if (len < 30720) chunkIdxLookup[i] = 9;
    else chunkIdxLookup[i] = 10;
}
const lowerBounds = new Uint16Array([256, 512, 1024, 2048, 3072, 4096, 6144, 8192, 12288, 20480, 28672]);
const manualPipe = async (readable, writable) => {
    const safeBufferSize = bufferSize - maxChunkLen;
    let buffer = new Uint8Array(bufferSize + 512), chunkBuf = new ArrayBuffer(maxChunkLen);
    let offset = 0, totalBytes = 0, timerId = null, resume = null, dynamicLowerBound = 4096;
    let globalBytes = new Float64Array(11), currentMaxIdx = 4, statBytes = 0;
    const flushBuffer = () => {
        offset > 0 && (writable.send(buffer.slice(0, offset)), offset = 0);
        timerId && (clearTimeout(timerId), timerId = null), resume?.(), resume = null;
    };
    const reader = readable.getReader({mode: 'byob'});
    try {
        while (true) {
            const {done, value} = await reader.read(new Uint8Array(chunkBuf));
            if (done) break;
            chunkBuf = value.buffer;
            const chunkLen = value.byteLength, idx = chunkIdxLookup[chunkLen >> 8];
            globalBytes[idx] += chunkLen, statBytes += chunkLen;
            globalBytes[idx] > globalBytes[currentMaxIdx] && (currentMaxIdx = idx, dynamicLowerBound = lowerBounds[idx]);
            if (statBytes > 524288000) {
                statBytes = 0;
                let newMaxIdx = 0;
                for (let i = 0; i < 11; i++) (globalBytes[i] /= 2) > globalBytes[newMaxIdx] && (newMaxIdx = i);
                currentMaxIdx = newMaxIdx, dynamicLowerBound = lowerBounds[newMaxIdx];
            }
            if (chunkLen < 512) {
                offset > 0 ? (buffer.set(value, offset), offset += chunkLen, flushBuffer()) : writable.send(value.slice());
            } else {
                chunkLen < dynamicLowerBound && (totalBytes = 0);
                buffer.set(value, offset), offset += chunkLen, totalBytes += chunkLen;
                timerId ||= setTimeout(flushBuffer, flushTime);
                if (totalBytes < startThreshold) {
                    offset > safeBufferSize && flushBuffer();
                } else {
                    offset > safeBufferSize && (await new Promise(r => resume = r));
                }
            }
        }
    } finally {flushBuffer(), reader.releaseLock()}
};
const handleWebSocketConn = async (webSocket, request) => {
    const requestURL = new URL(request.url);
    const reqCipher = (requestURL.searchParams.get('enc') || '').toLowerCase();
    const ssConfig = ssCipherConfigs[reqCipher];
    const ssAeadEnabled = !!ssConfig;
    const protocolHeader = request.headers.get('sec-websocket-protocol');
    // @ts-ignore
    const earlyData = (!ssAeadEnabled && protocolHeader) ? Uint8Array.fromBase64(protocolHeader, {alphabet: 'base64url'}) : null;
    let tcpWrite, processingChain = Promise.resolve(), parsedRequest, tcpSocket;
    const closeSocket = () => {if (!earlyData) {tcpSocket?.close(), webSocket?.close()}};
    if (ssAeadEnabled) {
        const ssDecryptor = createSsInboundDecryptor(ssConfig, uuid);
        let ssEncryptor = null;
        let sendQueue = Promise.resolve();
        const ssReplySocket = {
            send(data) {
                const chunk = ssToUint8(data);
                sendQueue = sendQueue.then(async () => {
                    if (webSocket.readyState !== WebSocket.OPEN) return;
                    if (!ssEncryptor) ssEncryptor = await createSsOutboundEncryptor(ssConfig, uuid);
                    const encrypted = await ssEncryptor.encrypt(chunk);
                    if (encrypted.byteLength) webSocket.send(encrypted);
                }).catch(() => closeSocket());
            }
        };
        const processSs = async (chunk) => {
            const plainChunkList = await ssDecryptor.input(new Uint8Array(chunk));
            for (let i = 0; i < plainChunkList.length; i++) {
                const plainChunk = plainChunkList[i];
                if (tcpWrite) {
                    await tcpWrite(plainChunk);
                } else {
                    try {
                        parsedRequest = parseRequestData(plainChunk);
                        if (parsedRequest) {
                            ssReplySocket.send(new Uint8Array([plainChunk[0], 0]));
                        } else if (plainChunk.length > 58 && plainChunk[56] === 13 && plainChunk[57] === 10) {
                            parsedRequest = parseTransparent(plainChunk);
                        } else {
                            parsedRequest = parseShadow(plainChunk);
                        }
                        if (!parsedRequest) return closeSocket();
                        const payload = plainChunk.subarray(parsedRequest.dataOffset);
                        tcpSocket = await establishTcpConnection(parsedRequest, request);
                        if (!tcpSocket) return closeSocket();
                        const tcpWriter = tcpSocket.writable.getWriter();
                        if (payload.byteLength) await tcpWriter.write(payload);
                        tcpWrite = (tcpChunk) => tcpWriter.write(tcpChunk);
                        manualPipe(tcpSocket.readable, ssReplySocket);
                    } catch {return closeSocket()}
                }
            }
        };
        webSocket.addEventListener("message", event => {processingChain = processingChain.then(() => processSs(event.data).catch(closeSocket))});
        return;
    }
    const processMessage = async (chunk) => {
        try {
            if (tcpWrite) return tcpWrite(chunk);
            chunk = earlyData ? chunk : new Uint8Array(chunk);
            if (chunk.length > 58 && chunk[56] === 13 && chunk[57] === 10) {
                parsedRequest = parseTransparent(chunk);
            } else if ((parsedRequest = parseRequestData(chunk))) {
                webSocket.send(new Uint8Array([chunk[0], 0]));
            } else {parsedRequest = parseShadow(chunk)}
            if (!parsedRequest) return closeSocket();
            const payload = chunk.subarray(parsedRequest.dataOffset);
            tcpSocket = await establishTcpConnection(parsedRequest, request);
            if (!tcpSocket) return closeSocket();
            const tcpWriter = tcpSocket.writable.getWriter();
            if (payload.byteLength) tcpWriter.write(payload);
            tcpWrite = (chunk) => tcpWriter.write(chunk);
            manualPipe(tcpSocket.readable, webSocket);
        } catch {closeSocket()}
    };
    if (earlyData) processingChain = processingChain.then(() => processMessage(earlyData));
    webSocket.addEventListener("message", event => processingChain = processingChain.then(() => processMessage(event.data)));
};
export default {
    async fetch(request) {
        if (request.headers.get('Upgrade') === 'websocket') {
            const {0: clientSocket, 1: webSocket} = new WebSocketPair();
            // @ts-ignore
            webSocket.accept({allowHalfOpen: true}), webSocket.binaryType = "arraybuffer";
            handleWebSocketConn(webSocket, request);
            return new Response(null, {status: 101, webSocket: clientSocket});
        }
        return new Response(html, {status: 404, headers: {'Content-Type': 'text/html; charset=UTF-8'}});
    }
};