import hashlib, hmac, opEndpoint, time
from lxml import etree
from testid import *

class application:
  class __metaclass__(opEndpoint.application.__metaclass__):
    def checkidSetup(ctx, environ, params):
      host = environ['HTTP_HOST']
      target = environ['PATH_INFO']

      try:
        end = target.index('/', 1)

      except ValueError:
        base = target

      else:
        base = target[:end]

      assocHandle = str(params['openid.assoc_handle'])
      returnTo = str(params['openid.return_to'])

      signed = [
        ('assoc_handle', assocHandle),
        ('claimed_id', 'http://{}{}/claimedIdentifier'.format(host, base)),
        ('identity', 'http://{}{}/claimedIdentifier'.format(host, base)),
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
