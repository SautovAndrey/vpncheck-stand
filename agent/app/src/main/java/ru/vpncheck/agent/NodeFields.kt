package ru.vpncheck.agent

object NodeFields {
    val FIELDS: Map<String, Map<String, String>> = mapOf(
        "outbound" to mapOf(
            "tag" to "", "protocol" to "", "settings" to "@settings", "streamSettings" to "@stream",
            "proxySettings" to "@proxySettings", "mux" to "@mux", "sendThrough" to "!",
        ),
        "proxySettings" to mapOf(
            "tag" to "", "transportLayer" to "",
        ),
        "mux" to mapOf(
            "enabled" to "", "concurrency" to "", "xudpConcurrency" to "", "xudpProxyUDP443" to "",
        ),
        "settings.vless" to mapOf(
            "address" to "", "port" to "", "id" to "", "flow" to "", "encryption" to "", "level" to "", "email" to "",
            "vnext" to "@vnext.vless",
        ),
        "vnext.vless" to mapOf(
            "address" to "", "port" to "", "users" to "@user.vless",
        ),
        "user.vless" to mapOf(
            "id" to "", "flow" to "", "encryption" to "", "level" to "", "email" to "", "security" to "",
        ),
        "settings.vmess" to mapOf(
            "address" to "", "port" to "", "id" to "", "security" to "", "level" to "", "email" to "", "experiments" to "",
            "vnext" to "@vnext.vmess",
        ),
        "vnext.vmess" to mapOf(
            "address" to "", "port" to "", "users" to "@user.vmess",
        ),
        "user.vmess" to mapOf(
            "id" to "", "security" to "", "alterId" to "", "level" to "", "email" to "", "experiments" to "",
        ),
        "settings.trojan" to mapOf(
            "address" to "", "port" to "", "password" to "", "level" to "", "email" to "", "flow" to "",
            "servers" to "@server.trojan",
        ),
        "server.trojan" to mapOf(
            "address" to "", "port" to "", "password" to "", "level" to "", "email" to "", "flow" to "",
        ),
        "settings.shadowsocks" to mapOf(
            "address" to "", "port" to "", "method" to "", "password" to "", "level" to "", "email" to "", "uot" to "",
            "UoTVersion" to "", "servers" to "@server.shadowsocks",
        ),
        "server.shadowsocks" to mapOf(
            "address" to "", "port" to "", "method" to "", "password" to "", "level" to "", "email" to "", "uot" to "",
            "UoTVersion" to "",
        ),
        "settings.hysteria" to mapOf(
            "version" to "", "address" to "", "port" to "",
        ),
        "settings.freedom" to mapOf(
            "domainStrategy" to "", "fragment" to "@fragment", "noises" to "@noise", "userLevel" to "", "redirect" to "",
        ),
        "fragment" to mapOf(
            "packets" to "", "length" to "", "interval" to "", "maxSplit" to "",
        ),
        "noise" to mapOf(
            "type" to "", "packet" to "", "delay" to "", "applyTo" to "",
        ),
        "stream" to mapOf(
            "network" to "", "security" to "", "tlsSettings" to "@tls", "realitySettings" to "@reality", "rawSettings" to "@raw",
            "tcpSettings" to "@raw", "xhttpSettings" to "@xhttp", "splithttpSettings" to "@xhttp", "kcpSettings" to "@kcp",
            "grpcSettings" to "@grpc", "wsSettings" to "@ws", "httpupgradeSettings" to "@httpupgrade",
            "hysteriaSettings" to "@hysteria", "sockopt" to "@sockopt",
        ),
        "download" to mapOf(
            "address" to "", "port" to "", "network" to "", "security" to "", "tlsSettings" to "@tls",
            "realitySettings" to "@reality", "rawSettings" to "@raw", "tcpSettings" to "@raw", "xhttpSettings" to "@xhttp",
            "splithttpSettings" to "@xhttp", "kcpSettings" to "@kcp", "grpcSettings" to "@grpc", "wsSettings" to "@ws",
            "httpupgradeSettings" to "@httpupgrade", "hysteriaSettings" to "@hysteria", "sockopt" to "@sockopt",
        ),
        "xhttp" to mapOf(
            "host" to "", "path" to "", "mode" to "", "headers" to "*", "xPaddingBytes" to "", "xPaddingObfsMode" to "",
            "xPaddingKey" to "", "xPaddingHeader" to "", "xPaddingPlacement" to "", "xPaddingMethod" to "",
            "uplinkHTTPMethod" to "", "sessionIDPlacement" to "", "sessionIDKey" to "", "sessionIDTable" to "",
            "sessionIDLength" to "", "seqPlacement" to "", "seqKey" to "", "uplinkDataPlacement" to "", "uplinkDataKey" to "",
            "uplinkChunkSize" to "", "noGRPCHeader" to "", "noSSEHeader" to "", "scMaxEachPostBytes" to "",
            "scMinPostsIntervalMs" to "", "scMaxBufferedPosts" to "", "scStreamUpServerSecs" to "", "serverMaxHeaderBytes" to "",
            "xmux" to "@xmux", "downloadSettings" to "@download", "extra" to "@xhttpExtra",
        ),
        "xhttpExtra" to mapOf(
            "host" to "", "path" to "", "mode" to "", "headers" to "*", "xPaddingBytes" to "", "xPaddingObfsMode" to "",
            "xPaddingKey" to "", "xPaddingHeader" to "", "xPaddingPlacement" to "", "xPaddingMethod" to "",
            "uplinkHTTPMethod" to "", "sessionIDPlacement" to "", "sessionIDKey" to "", "sessionIDTable" to "",
            "sessionIDLength" to "", "seqPlacement" to "", "seqKey" to "", "uplinkDataPlacement" to "", "uplinkDataKey" to "",
            "uplinkChunkSize" to "", "noGRPCHeader" to "", "noSSEHeader" to "", "scMaxEachPostBytes" to "",
            "scMinPostsIntervalMs" to "", "scMaxBufferedPosts" to "", "scStreamUpServerSecs" to "", "serverMaxHeaderBytes" to "",
            "xmux" to "@xmux", "downloadSettings" to "@download",
        ),
        "xmux" to mapOf(
            "maxConcurrency" to "", "maxConnections" to "", "cMaxReuseTimes" to "", "hMaxRequestTimes" to "",
            "hMaxReusableSecs" to "", "hKeepAlivePeriod" to "",
        ),
        "raw" to mapOf(
            "header" to "@tcpHeader", "acceptProxyProtocol" to "",
        ),
        "tcpHeader" to mapOf(
            "type" to "", "request" to "@httpRequest", "response" to "@httpResponse",
        ),
        "httpRequest" to mapOf(
            "version" to "", "method" to "", "path" to "", "headers" to "*",
        ),
        "httpResponse" to mapOf(
            "version" to "", "status" to "", "reason" to "", "headers" to "*",
        ),
        "kcp" to mapOf(
            "mtu" to "", "tti" to "", "uplinkCapacity" to "", "downlinkCapacity" to "", "cwndMultiplier" to "",
            "maxSendingWindow" to "", "congestion" to "", "readBufferSize" to "", "writeBufferSize" to "",
            "header" to "@kcpHeader", "seed" to "",
        ),
        "kcpHeader" to mapOf(
            "type" to "", "domain" to "",
        ),
        "grpc" to mapOf(
            "authority" to "", "serviceName" to "", "multiMode" to "", "idle_timeout" to "", "health_check_timeout" to "",
            "permit_without_stream" to "", "initial_windows_size" to "", "user_agent" to "",
        ),
        "ws" to mapOf(
            "host" to "", "path" to "", "headers" to "*", "acceptProxyProtocol" to "", "heartbeatPeriod" to "",
        ),
        "httpupgrade" to mapOf(
            "host" to "", "path" to "", "headers" to "*", "acceptProxyProtocol" to "",
        ),
        "hysteria" to mapOf(
            "version" to "", "auth" to "", "congestion" to "", "up" to "", "down" to "", "udphop" to "@udpHop",
            "udpIdleTimeout" to "",
        ),
        "udpHop" to mapOf(
            "ports" to "", "interval" to "",
        ),
        "tls" to mapOf(
            "serverName" to "", "alpn" to "", "fingerprint" to "", "echConfigList" to "", "echForceQuery" to "",
            "pinnedPeerCertSha256" to "", "verifyPeerCertByName" to "", "minVersion" to "", "maxVersion" to "",
            "cipherSuites" to "", "curvePreferences" to "", "enableSessionResumption" to "", "disableSystemRoot" to "",
            "allowInsecure" to "",
        ),
        "reality" to mapOf(
            "serverName" to "", "fingerprint" to "", "publicKey" to "", "password" to "", "shortId" to "", "spiderX" to "",
            "mldsa65Verify" to "", "show" to "",
        ),
        "sockopt" to mapOf(
            "dialerProxy" to "", "domainStrategy" to "", "happyEyeballs" to "@happyEyeballs", "tcpFastOpen" to "",
            "tcpKeepAliveInterval" to "", "tcpKeepAliveIdle" to "", "tcpCongestion" to "", "tcpWindowClamp" to "",
            "tcpMaxSeg" to "", "tcpUserTimeout" to "", "tcpMptcp" to "", "tcpNoDelay" to "", "penetrate" to "", "v6only" to "",
            "acceptProxyProtocol" to "", "addressPortStrategy" to "", "mark" to "", "interface" to "", "customSockopt" to "",
            "tproxy" to "!off",
        ),
        "happyEyeballs" to mapOf(
            "prioritizeIPv6" to "", "tryDelayMs" to "", "interleave" to "", "maxConcurrentTry" to "",
        ),
    )
}
