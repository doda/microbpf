/*
 * Example NET_RX Filter Program
 *
 * Drops packets whose first byte is 0xFF.
 */

function mbpf_prog(ctx) {
    // Drop packets whose first byte is 0xFF (toy example)
    if (ctx.pkt_len < 1)
        return 0; // PASS

    var b0 = ctx.readU8(0);
    if (b0 === 0xFF)
        return 1; // DROP

    return 0; // PASS
}
