#!/usr/local/bin/python

from socket import *
from re import match
from random import randint


def random():
    randint(1, 9)


DNS_ERROR = 'DNS_ERROR'
DNS_NAME = 'DNS_NAME'
DNS_REFUSED = 'DNS_REFUSED'


# DNS types conversions

def dns_type_string(dns_type):
    try:
        return {
            1: 'A',
            2: 'NS',
            3: 'MD',
            4: 'MF',
            5: 'CNAME',
            6: 'SOA',
            7: 'MB',
            8: 'MG',
            9: 'MR',
            10: 'NULL',
            11: 'WKS',
            12: 'PTR',
            13: 'HINFO',
            14: 'MINFO',
            15: 'MX',
            16: 'TXT',
            252: 'AXFR',
            253: 'MAILB',
            254: 'MAILA',
            255: '*'
        }[dns_type]
    except KeyError:
        raise DNS_ERROR('Unknown dns-type %d' % dns_type)


def string_dns_type(str):
    str = str.upper()
    try:
        return {
            'A': 1,
            'NS': 2,
            'MD': 3,
            'MF': 4,
            'CNAME': 5,
            'SOA': 6,
            'MB': 7,
            'MG': 8,
            'MR': 9,
            'NULL': 10,
            'WKS': 11,
            'PTR': 12,
            'HINFO': 13,
            'MINFO': 14,
            'MX': 15,
            'TXT': 16,
            'AXFR': 252,
            'MAILB': 253,
            'MAILA': 254,
            '*': 255,
            'ANY': 255
        }[str]
    except KeyError:
        raise DNS_ERROR('Unknown dns-type %s' % str)


# Auxiliary functions
def is_bit(x):
    return x == 0 or x == 1


def get_value(w):
    result = ord(w[0])
    w = w[1:]
    while w:
        result = result * 256 + ord(w[0])
        w = w[1:]
    return result


def set_value(v, bts):
    if v >= pow(256, bts):
        raise DNS_ERROR("Can't fit %d into %d 8-bit bytes" % (v, bts))
    if v < 0:
        raise DNS_ERROR("%d is a negative value" % v)
    v, b = divmod(v, 256)
    result = chr(b)
    while v > 0:
        v, b = divmod(v, 256)
        result = chr(b) + result
    return chr(0) * (bts - len(result)) + result


# Flags section
def make_flags(qr, opcode, aa, tc, rd, ra, rcode):
    # Test arguments
    if not (is_bit(qr) and is_bit(aa) and is_bit(tc) and is_bit(rd) and is_bit(ra)) or not (opcode == 0 or opcode == 1
                                                                                            or opcode == 2) \
            or not (0 <= rcode <= 15):
        raise DNS_ERROR('Invalid argument, or arguments')
    left = 128 * qr + 8 * opcode + 4 * aa + 2 * tc + rd
    right = 128 * ra + rcode
    return chr(left) + chr(right)


def parse_flags(reply):
    if not type(reply) == type('') and len(reply) == 2:
        raise DNS_ERROR('Invalid argument, or arguments')

    left = ord(reply[0])
    right = ord(reply[1])

    qr = (left & 128) >> 7
    opcode = (left & 120) >> 3
    aa = (left & 4) >> 2
    tc = (left & 2) >> 1
    rd = (left & 1)
    ra = (right & 128) >> 7
    rcode = (right & 15)
    return qr, opcode, aa, tc, rd, ra, rcode


def make_hostname(hostname):
    result = ''
    mlen = match('[^.]*', hostname)

    while mlen:
        result = result + chr(mlen) + hostname[0:mlen]
        hostname = hostname[mlen + 1:]
        mlen = match('[^.]*', hostname)
    return result + chr(0)


def parse_string(record, index=0):
    c = ord(record[index])
    return record[index + 1:index + 1 + c]


def size_string(record, index=0):
    return ord(record[index]) + 1


def parse_domain(record, index=0):
    c = ord(record[index])
    if c == 0:
        return ''
    if c < 63:
        name = record[index + 1:index + 1 + c]
        rest = parse_domain(record, index + 1 + c)
        if rest:
            return name + '.' + rest
        else:
            return name
    offset = ((c & 63) << 8) + ord(record[index + 1])
    return parse_domain(record, offset)


def size_domain(record, index):
    c = ord(record[index])
    if c == 0:
        return 1
    if c > 63:
        return 2
    return c + 1 + size_domain(record, index + 1 + c)


def parse_query(record, idx):
    """Parse one query, and return the query and the length of the entry"""
    domain = parse_domain(record, idx)
    size = size_domain(record, idx)
    dns_type = get_value(record[idx + size:idx + size + 2])
    dns_class = get_value(record[idx + size + 2:idx + size + 4])
    if dns_class != 1:
        raise DNS_ERROR('Unable to handle query-class different from INET')
    return size + 4, domain, dns_type, dns_class


def parse_resource(record, idx):
    domain = parse_domain(record, idx)
    size = size_domain(record, idx)
    idx = idx + size
    dns_type = dns_type_string(get_value(record[idx:idx + 2]))
    dns_class = get_value(record[idx + 2:idx + 4])
    if dns_class != 1:
        raise DNS_ERROR('Unable to handle resource-class different from INET')
    ttl = get_value(record[idx + 4:idx + 8])
    l = get_value(record[idx + 8:idx + 10])
    o = idx + 10
    return size + 10 + l, domain, dns_type, dns_class, ttl, (l, o)


def make_query(dns_type, domain):
    # Check argument
    if not (dns_type == 1 or dns_type == 2 or dns_type == 5 or \
                        dns_type == 12 or dns_type == 13 or dns_type == 15 or \
                        dns_type == 252 or dns_type == 255):
        raise DNS_ERROR('Invalid type %d when creating query')

    # Create an identity
    identity = chr(256 * random()) + chr(256 * random())
    # A standard query that wants recursion
    flags = make_flags(0, 0, 0, 0, 1, 0, 0)
    # Number of querys
    one_query = '\000\001'
    header = identity + flags + one_query + 6 * '\000'
    query = make_hostname(domain) + chr(0) + chr(dns_type) + '\000\001'
    return header + query


def parse_header(record, idx=0):
    id = get_value(record[idx:idx + 2])
    flags = parse_flags(record[idx + 2:idx + 4])
    queries = get_value(record[idx + 4:idx + 6])
    answers = get_value(record[idx + 6:idx + 8])
    authorities = get_value(record[idx + 8:idx + 10])
    additionals = get_value(record[idx + 10:idx + 12])
    return id, flags, queries, answers, authorities, additionals


def parse_wks(bitmap):
    offset = 0
    wks = []
    for char in bitmap:
        byte = ord(char)
        if byte & 128:
            wks.append(offset)
        if byte & 64:
            wks.append(offset + 1)
        if byte & 32:
            wks.append(offset + 2)
        if byte & 16:
            wks.append(offset + 3)
        if byte & 8:
            wks.append(offset + 4)
        if byte & 4:
            wks.append(offset + 5)
        if byte & 2:
            wks.append(offset + 6)
        if byte & 1:
            wks.append(offset + 7)
        offset += 8
    return wks


def parse_dns(record):
    header = parse_header(record)
    # Parse queries
    count = header[2]
    i = 0
    loc = 12
    queries = list()

    while i < count:
        (size, domain, dns_type, dns_class) = parse_query(record, loc)
        queries.append((domain, dns_type, dns_class))
        loc += size
        i += 1
    records = []
    count = header[3] + header[4] + header[5]
    i = 0
    while i < count:
        (size, domain, dns_type, dns_class, ttl, (length, offset)) = \
            parse_resource(record, loc)
        if dns_type == 'A':  # A type
            data = record[offset:offset + length]
            data = '%d.%d.%d.%d' % \
                   (ord(data[0]), ord(data[1]), ord(data[2]), ord(data[3]))
        elif dns_type == 'NS':  # NS type
            data = parse_domain(record, offset)
        elif dns_type == 'MD':  # MD (Obsolete)
            data = parse_domain(record, offset)
        elif dns_type == 'MF':  # MF (Obsolete)
            data = parse_domain(record, offset)
        elif dns_type == 'CNAME':  # CNAME type
            data = parse_domain(record, offset)
        elif dns_type == 'SOA':  # SOA type
            mname = parse_domain(record, offset)
            offset += size_domain(record, offset)
            rname = parse_domain(record, offset)
            offset += size_domain(record, offset)
            refresh = get_value(record[offset:offset + 4])
            retry = get_value(record[offset + 4:offset + 8])
            expire = get_value(record[offset + 8:offset + 12])
            minimum = get_value(record[offset + 12:offset + 16])
            data = (mname, rname, refresh, retry, expire, minimum)
        elif dns_type == 'MB':  # MB (exprimental)
            data = parse_domain(record, offset)
        elif dns_type == 'MG':  # MG (exprimental)
            data = parse_domain(record, offset)
        elif dns_type == 'MR':  # MR (exprimental)
            data = parse_domain(record, offset)
        elif dns_type == 'NULL':  # NULL (exprimental)
            data = parse_domain(record, offset)
        elif dns_type == 'WKS':  # WKS
            ip = record[offset:offset + length]
            ip = "%d.%d.%d.%d" % \
                 (ord(ip[0]), ord(ip[1]), ord(ip[2]), ord(ip[3]))
            proto = get_value(record[offset + 4:offset + 6])
            bitmap = record[offset + 6:offset + length]
            wks = parse_wks(record[offset + 6:offset + length])
            data = (ip, proto, wks)
        elif dns_type == 'PTR':  # PTR
            data = parse_domain(record, offset)
        elif dns_type == 'HINFO':  # HINFO
            cpu = parse_string(record, offset)
            os = parse_string(record, offset + size_string(record, offset))
            data = (cpu, os)
        elif dns_type == 'MINFO':  # MINFO
            rmailbx = parse_domain(record, offset)
            emailbx = parse_domain(record, offset + size_domain(record, offset))
            data = (rmailbx, emailbx)
        elif dns_type == 'MX':  # MX type
            mx = get_value(record[offset:offset + 2])
            host = parse_domain(record, offset + 2)
            data = (mx, host)
        elif dns_type == 'TXT':  # TXT type
            data = []
            i = 0
            while i < length:
                data.append(parse_string(record[offset + i]))
                i += size_string(record[offset + i])
        else:
            raise DNS_ERROR('Unknown resource type')
        records.append((domain, dns_type, dns_class, ttl, data))
        loc += size
        i += 1
    return header, queries, records


def mx_query(domain, DNS='sunic.sunet.se'):
    data = dns_query(15, domain, DNS)
    (header, queries, resources) = parse_dns(data)
    (id, flags, q_count, an_count, au_count, ad_count) = header
    (qr, opcode, aa, tc, rd, ra, rcode) = flags
    if rcode == 3:
        raise DNS_NAME('No such name "%s" in MX-query' % domain)
    if rcode == 0:
        result = []
        for resource in resources:
            dns_type = resource[1]
            if dns_type == 'MX':  # MX
                result.append(resource[4])
                # 	    else :
                # 		result.append(resource)
        return result
    else:
        raise DNS_ERROR('Unknown RCODE %d in MX-query "%s"' % (rcode, domain))


def any_query(domain, DNS='sunic.sunet.se'):
    data = dns_query(255, domain, DNS)
    (header, queries, resources) = parse_dns(data)
    (id, flags, q_count, an_count, au_count, ad_count) = header
    (qr, opcode, aa, tc, rd, ra, rcode) = flags
    if rcode == 3:
        raise DNS_NAME('No such name "%s" in ANY-query' % domain)
    if rcode == 0:
        return resources
    else:
        raise DNS_ERROR('Unknown RCODE %d in MX-query "%s"' % (rcode, domain))


def dns_query(dns_type, domain, DNS='sunic.sunet.se', TYPE='udp'):
    TYPE = TYPE.lower()
    if type(dns_type) == type(''):
        dns_type = string_dns_type(dns_type)
    query = make_query(dns_type, domain)
    if TYPE == 'udp':
        s = socket(AF_INET, SOCK_DGRAM)
        PORT = getservbyname('domain', TYPE)
        addr = (DNS, PORT)
        s.sendto(query, addr)
        data, fromaddr = s.recvfrom(1024)
        size = len(data)
        s.close()
    elif TYPE == 'tcp':
        s = socket(AF_INET, SOCK_STREAM)
        PORT = getservbyname('domain', TYPE)
        s.connect(DNS, PORT)
        (s1, s2) = divmod(len(query), 256)
        query = chr(s1) + chr(s2) + query
        s.send(query)
        data = s.recv(512)
        size = ord(data[0]) * 256 + ord(data[1])
        result = data[2:]
        s.setblocking(0)
        data = s.recv(512)
        while len(data) == 512:
            print("Fetching more")
            result = result + data
            data = s.recv(512)
        result = result + data
        s.close()
        data = result
    else:
        raise DNS_ERROR('Unknown datatype "%s"' % TYPE)

    (qr, opcode, aa, tc, rd, ra, rcode) = parse_header(data)[1]
    if rcode != 0:
        if rcode == 1:
            raise DNS_RCODE('Format error, server unable to interpret query')
        elif rcode == 2:
            raise DNS_RCODE('Server failure, server unable to process query')
        elif rcode == 3:
            raise DNS_NAME('Name error, domain does not exists')
        elif rcode == 4:
            raise DNS_RCODE('Server does not implement that type of query')
        elif rcode == 5:
            if TYPE == 'udp':
                return dns_query(dns_type, domain, DNS, 'tcp')
            raise DNS_REFUSE('Query refused, server refused to answer query')
        else:
            raise DNS_RCODE("Unable tp parse return-code %d" % rcode)
    if tc and TYPE == 'udp':
        return dns_query(dns_type, domain, DNS, 'tcp')
    return (size, data)


def truncated(record):
    return (ord(record[2]) & 2) >> 1


def print_header(header):
    if type(header) == type(''):
        (id, (qr, opcode, aa, tc, rd, ra, rcode), queries, answers, auth, add) = \
            parse_header(header)
    else:
        (id, (qr, opcode, aa, tc, rd, ra, rcode), queries, answers, auth, add) = header

    print('Id: %04x ' % id)

    if qr:
        print('Answer'),
    else:
        print('Query'),

    if aa:
        print('Authorative'),
    else:
        print('Non-authorative'),
    if tc: print('Truncated')

    print('Recursion('),
    if rd: print('wanted'),
    if ra: print('availible'),
    print(')'),

    print('Op-code: %d Return-code: %d' % (opcode, rcode))
    print('Questions:', queries),
    print('Answers:', answers),
    print('Authority:', auth),
    print('Additional:', add)


def print_dns(record):
    (header, queries, resources) = parse_dns(record)
    print_header(record[0:12])
    for x in queries:
        print('Query:', x)
    for x in resources:
        print('Resource:', x)


def hex_byte(o):
    if o < 16:
        return '0' + hex(o)[2:]
    else:
        return hex(o)[2:]


def print_hex_chunk(offset, chunk):
    values = [ord(chunk[0]), ord(chunk[1]), ord(chunk[2]), ord(chunk[3])]
    hex_values = hex_byte(values[0]) + hex_byte(values[1]) + \
                 hex_byte(values[2]) + hex_byte(values[3])
    string = ''
    for c in values:
        if 32 < c < 127:
            string += chr(c)
        else:
            string += ' '
    print(
        "%4d: '%s' %03d %03d %03d %03d %s" % \
        (offset, string, values[0], values[1], values[2], values[3], hex_values))


def print_hex(record):
    i = 0
    length = len(record)
    if length == 0:
        print("--- Empty record ---")
    while i + 4 < length:
        print_hex_chunk(i, record[i:i + 4])
        i += 4
    chunk = record[i:]
    if len(chunk) == 1:
        chunk = chunk + chr(255) + chr(255) + chr(255)
    elif len(chunk) == 2:
        chunk = chunk + chr(255) + chr(255)
    elif len(chunk) == 3:
        chunk += chr(255)
    elif len(chunk) != 4:
        raise DNS_ERROR('Unsizeable chunk in print_hex')
    print_hex_chunk(i, chunk)


def transfer_zone(domain, DNS='sunic.sunet.se'):
    (size, data) = dns_query('AXFR', domain, DNS, 'tcp')
    print("Size: %d data size: %d" % (size, len(data)))
    first = data[0:size]
    record = ''
    result = [parse_dns(first)]
    while record != first:
        data = data[size:]
        size = ord(data[0]) * 256 + ord(data[1])
        data = data[2:]
        record = data[0:size]
        result.append(parse_dns(record))
    return result


if __name__ == '__main__':
    for name in ['pson.pp.se', 'udac.se', 'telia.com']:
        print('--- %s ---' % name)
        zone = transfer_zone(name, 'ns1.udac.se')
        for (header, queries, resources) in zone:
            print_header(header)
            for x in queries:
                print('Query:', x)
            for x in resources:
                print('Resource:', x)
