from testid import *

# The attribute exchange namespace "http://openid.net/srv/ax/1.0" SHOULD be
# listed as an <xrd:Type> child element of the <xrd:Service> element in the
# XRDS discovery document

def application(environ, start_response):
  host = environ['HTTP_HOST']
  target = environ['PATH_INFO']

  try:
    end = target.index('/', 1)

  except ValueError:
    base = target

  else:
    base = target[:end]

  start_response('200', [('Content-Type', 'application/xrds+xml')])

  return ''.join((
    '<XRDS xmlns="xri://$xrds">',
      '<XRD xmlns="xri://$xrd*($v*2.0)">',
        '<Service>',
          '<Type>http://specs.openid.net/auth/2.0/signon</Type>',
          '<Type>http://openid.net/srv/ax/1.0</Type>',
          '<URI>http://{}{}/{}</URI>'.format(host, base, segment),
        '</Service>',
      '</XRD>',
    '</XRDS>'))
