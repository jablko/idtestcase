from idtestcase import *

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
          '<Type>http://specs.openid.net/auth/2.0/server</Type>',
          '<URI>http://{}{}/{}</URI>'.format(host, base, segment),
        '</Service>',
      '</XRD>',
    '</XRDS>'))
