package com.ccs.mint.plugin;

/** Private Binder protocol. No object deserialization or host Session handles. */
final class SandboxProtocol {
    static final String SERVICE = "com.ccs.mint.plugin.worker.v1";
    static final String RESULT = "com.ccs.mint.plugin.result.v1";
    static final int HELLO = 1, RUN = 2, DELIVER = 1, VERSION = 1;
    static final int MAX_REQUEST_BYTES = 16 * 1024;
    static final int MAX_RESPONSE_BYTES = 64 * 1024;
    static final int MAX_RESULT_CHARS = 24000;
    private SandboxProtocol() {}
}
