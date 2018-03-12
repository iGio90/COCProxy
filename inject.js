setTimeout(function() {
    inject();
}, 0)

function ba2hex(bufArray) {
    var uint8arr = new Uint8Array(bufArray);
    if (!uint8arr) {
        return '';
    }

    var hexStr = '';
    for (var i = 0; i < uint8arr.length; i++) {
        var hex = (uint8arr[i] & 0xff).toString(16);
        hex = (hex.length === 1) ? '0' + hex : hex;
        hexStr += hex;
    }

    return hexStr.toUpperCase();
}

function chainAttach(base) {
    var pt1 = ptr(parseInt(base) + 1 + 0x313AEC);
    var pt1_2 = ptr(parseInt(base) + 1 + 0x313BC2);
    var pt2 = ptr(parseInt(base) + 1 + 0x004012EC);
    var pt3 = ptr(parseInt(base) + 1 + 0x00298288);

    // attaching memclr8 to skip jump the crc :P
    var pr_memclr8 = ptr(parseInt(base) + 0x00041970);
    var pr_addrinfo = ptr(parseInt(base) + 0x00041BE0)
    var pr_send = ptr(parseInt(base) + 0x00042030)

    Interceptor.attach(pr_addrinfo, function(args) {
        Memory.writeUtf8String(this.context.r0, 'igio90.com')
    })
    Interceptor.attach(pr_send, {
        onEnter: function (args) {
            var msgId = parseInt("0x" + ba2hex(Memory.readByteArray(ptr(args[1]), 2)));
            if (msgId < 10000 || msgId > 30000) {
                return;
            }
            if (msgId === 10100) {
                Interceptor.attach(pt1, function() {
                    var pk;
                    var sk;

                    Interceptor.detachAll();

                    Interceptor.attach(pt1_2, function() {
                        Interceptor.attach(pt2, {
                            onEnter: function (args) {
                                pk = args[0];
                                sk = args[1];
                            },
                            onLeave: function (retval) {
                                // write sk into pk
                                Memory.writeByteArray(pk, Memory.readByteArray(sk, 32))

                                send("0::::" + ba2hex(Memory.readByteArray(pk, 32)));
                                send("1::::" + ba2hex(Memory.readByteArray(sk, 32)));

                                Interceptor.detachAll();

                                var i = 0;
                                Interceptor.attach(pr_memclr8, {
                                    onEnter: function (args) {
                                        if (i == 15 && parseInt(args[1]) == 64) {
                                            i++;
                                            Interceptor.detachAll();

                                            var b2ret;
                                            Interceptor.attach(pt3, {
                                                onEnter: function (args) {
                                                    b2ret = args[0];
                                                    send("2::::" + ba2hex(Memory.readByteArray(ptr(parseInt(b2ret) + 132), 32)));
                                                    Interceptor.detachAll();
                                                }
                                            });
                                        } else if (parseInt(args[1]) == 64) {
                                            i++
                                        }
                                    }
                                });
                            }
                        });
                    })
                });
            }
        }
    });
}

function inject() {
    var base = Process.findModuleByName("libg.so").base;

    var pr_frck = ptr(parseInt(base) + 1 + 0x1629D8)
    var pr_frck_r = ptr(parseInt(base) + 1 + 0x1629E4)

    var pr_strncpm = ptr(parseInt(base) + 0x00041DC0)
    var pr_socket = ptr(parseInt(base) + 0x00041BF8)

    // kill coc frida detection
    var attached = false;
    Interceptor.attach(pr_frck, function() {
        this.context.r0 = 0xFF
        if (!attached) {
            attached = true;
            chainAttach(base);
        }
    });
    Interceptor.attach(pr_frck_r, function() {
        this.context.r0 = 0x2
    });
}