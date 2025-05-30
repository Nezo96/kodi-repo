import hashlib

_ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def _to64(v, n):
    result = ""
    while n > 0:
        result += _ITOA64[v & 0x3f]
        v >>= 6
        n -= 1
    return result

def md5_crypt(password, salt, magic="$1$"):
    # passlib-style: salt max 8 znakov, odstráni magic
    if salt.startswith(magic):
        salt = salt[len(magic):]
    salt = salt.split('$')[0]
    salt = salt[:8]
    password = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    magic_bytes = magic.encode('utf-8')

    # Start
    m = hashlib.md5()
    m.update(password)
    m.update(magic_bytes)
    m.update(salt_bytes)

    alt = hashlib.md5()
    alt.update(password)
    alt.update(salt_bytes)
    alt.update(password)
    alt_res = alt.digest()

    # Update md5 with alternate sum for each char in password
    pwlen = len(password)
    for i in range(pwlen):
        m.update(alt_res[i % 16:i % 16+1])

    # Do weird stuff depending on bits in pwlen
    i = pwlen
    while i:
        if i & 1:
            m.update(b'\x00')
        else:
            m.update(password[:1])
        i >>= 1

    final = m.digest()

    # 1000 rounds
    for i in range(1000):
        md5 = hashlib.md5()
        if i & 1:
            md5.update(password)
        else:
            md5.update(final)
        if i % 3:
            md5.update(salt_bytes)
        if i % 7:
            md5.update(password)
        if i & 1:
            md5.update(final)
        else:
            md5.update(password)
        final = md5.digest()

    # Rearrangement
    l = [
        (final[0] << 16) | (final[6] << 8) | final[12],
        (final[1] << 16) | (final[7] << 8) | final[13],
        (final[2] << 16) | (final[8] << 8) | final[14],
        (final[3] << 16) | (final[9] << 8) | final[15],
        (final[4] << 16) | (final[10] << 8) | final[5],
        final[11]
    ]
    passwd = ""
    passwd += _to64(l[0], 4)
    passwd += _to64(l[1], 4)
    passwd += _to64(l[2], 4)
    passwd += _to64(l[3], 4)
    passwd += _to64(l[4], 4)
    passwd += _to64(l[5], 2)

    return f"{magic}{salt}${passwd}"