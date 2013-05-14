import hashlib, hmac, os, time
from lxml import etree
from idtestcase import *

class application:
  def associate(ctx, environ, params):

    # ASCII characters in the range 33-126 inclusive (printable non-whitespace
    # characters)
    assocHandle = rndstr(6, map(chr, range(33, 126 + 1)))

    assocType = str(params['openid.assoc_type'])

    try:
      g = base64Dec(params['openid.dh_gen'])

    except KeyError:
      g = 2

    try:
      p = base64Dec(params['openid.dh_modulus'])

    except KeyError:

      # This is a confirmed-prime number, used as the default modulus for
      # Diffie-Hellman Key Exchange
      p = 0xdcf93a0b883972ec0e19989ac5a2ce310e1d37717e8d9571bb7623731866e61ef75a2e27898b057f9891c2e27a639c3f29b60814581cd3b2ca3986d2683705577d45c2e7e52dc81c7a171876e5cea74b1448bfdfaf18828efd2519f14e45e3826634af1949e5b535cc829a483b8a76223e5d490a257f05bdff16f2fb22c583ab

    # Random private key xb in the range [1 .. p-1]
    xb = int(random() * p)

    dhServerPublic = base64Enc(pow(g, xb, p))

    # The MAC key MUST be the same length as the output of H, the hash function
    # - 160 bits (20 bytes) for DH-SHA1 or 256 bits (32 bytes) for DH-SHA256,
    # as well as the output of the signature algorithm of this association

    if str(params['openid.session_type']) == 'DH-SHA1':
      H = hashlib.sha1()

      if assocType == 'HMAC-SHA1':
        macKey = os.urandom(20)

    elif str(params['openid.session_type']) == 'DH-SHA256':
      H = hashlib.sha256()

      if assocType == 'HMAC-SHA256':
        macKey = os.urandom(32)

    shared(assocHandle=assocHandle, macKey=macKey, assocType=assocType).put()

    H.update(btwocEnc(pow(base64Dec(params['openid.dh_consumer_public']), xb, p)))
    encMacKey = base64.b64encode(''.join(chr(ord(digest) ^ ord(macKey)) for digest, macKey in zip(H.digest(), macKey)))

    # 14 days in seconds
    expiresIn = 14 * 24 * 60 * 60

    return '\n'.join(map(':'.join, (
      ('assoc_handle', assocHandle),
      ('assoc_type', assocType),
      ('dh_server_public', dhServerPublic),
      ('enc_mac_key', encMacKey),
      ('expires_in', str(expiresIn)),
      ('ns', 'http://specs.openid.net/auth/2.0'),
      ('session_type', str(params['openid.session_type']))))) + '\n'

  def checkidSetup(ctx, environ, params):
    host = environ['HTTP_HOST']
    target = environ['PATH_INFO']

    assocHandle = str(params['openid.assoc_handle'])
    returnTo = str(params['openid.return_to'])

    signed = [
      ('assoc_handle', assocHandle),
      ('claimed_id', str(params['openid.claimed_id'])),
      ('identity', str(params['openid.identity'])),
      ('op_endpoint', 'http://{}{}'.format(host, target)),
      ('response_nonce', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())),
      ('return_to', returnTo)]

    assoc, = shared.gql('WHERE assocHandle = :1', assocHandle)

    signed.extend((
      ('mode', 'id_res'),
      ('ns', 'http://specs.openid.net/auth/2.0'),
      ('sig', base64.b64encode(hmac.new(assoc.macKey, '\n'.join(map(':'.join, signed)) + '\n', { 'HMAC-SHA1': hashlib.sha1, 'HMAC-SHA256': hashlib.sha256 }[assoc.assocType]).digest())),
      ('signed', ','.join(field for field, _ in signed))))

    form = etree.Element('form', action=returnTo, method='post')
    for k, v in signed:
      form.append(etree.Element('input', name='openid.' + k, value=v))

    return etree.tostring(form) + '<script>document.forms[0].submit()</script>'

  checkAuthentication = lambda ctx, environ, params: '\n'.join(map(':'.join, (
    ('is_valid', 'true'),
    ('ns', 'http://specs.openid.net/auth/2.0')))) + '\n'

  def __call__(ctx, environ, start_response):
    if environ['REQUEST_METHOD'] == 'POST':
      params = urlencoded(environ['wsgi.input'].read())

    else:
      params = urlencoded(environ['QUERY_STRING'])

    start_response('200', [])

    mode = str(params['openid.mode'])
    if mode == 'associate':
      return ctx.associate(environ, params)

    elif mode == 'checkid_setup':
      return ctx.checkidSetup(environ, params)

    elif mode == 'check_authentication':
      return ctx.checkAuthentication(environ, params)

application = application()
