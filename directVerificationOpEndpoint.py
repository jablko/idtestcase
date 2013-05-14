import hashlib, hmac, opEndpoint, os, time
from lxml import etree
from idtestcase import *

# If the Relying Party does not have an association stored, it MUST request
# that the OP verify the signature via Direct Verification

class application(opEndpoint.application.__class__):
  def checkidSetup(ctx, environ, params):
    host = environ['HTTP_HOST']
    target = environ['PATH_INFO']

    # ASCII characters in the range 33-126 inclusive (printable non-whitespace
    # characters)
    assocHandle = rndstr(6, map(chr, range(33, 126 + 1)))

    returnTo = str(params['openid.return_to'])

    signed = [
      ('assoc_handle', assocHandle),
      ('claimed_id', str(params['openid.claimed_id'])),
      ('identity', str(params['openid.identity'])),
      ('op_endpoint', 'http://{}{}'.format(host, target)),
      ('response_nonce', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())),
      ('return_to', returnTo)]

    macKey = os.urandom(32)

    signed.extend((
      ('mode', 'id_res'),
      ('ns', 'http://specs.openid.net/auth/2.0'),
      ('sig', base64.b64encode(hmac.new(macKey, '\n'.join(map(':'.join, signed)) + '\n', hashlib.sha256).digest())),
      ('signed', ','.join(field for field, _ in signed))))

    form = etree.Element('form', action=returnTo, method='post')
    for k, v in signed:
      form.append(etree.Element('input', name='openid.' + k, value=v))

    return etree.tostring(form) + '<script>document.forms[0].submit()</script>'

application = application()
