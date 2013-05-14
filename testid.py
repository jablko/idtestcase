import base64, pickle, urllib
from google.appengine.ext import db
from random import random

segment = 1

class shared(db.Model):
  assocHandle = db.StringProperty()
  assocType = db.StringProperty()
  macKey = db.ByteStringProperty()

btwocDec = lambda arg: pickle.decode_long(arg[::-1])
btwocEnc = lambda arg: pickle.encode_long(arg)[::-1] if arg else '\x00'

base64Dec = lambda arg: btwocDec(base64.b64decode(arg.replace('-', '+').replace('_', '/')))
base64Enc = lambda arg: base64.b64encode(btwocEnc(arg))

def rndstr(length, alphabet):
  result = ''

  # Choose symbols from alphabet at random
  symbol = random()
  for _ in range(length):
    symbol *= len(alphabet)
    result += alphabet[int(symbol)]
    symbol -= int(symbol)

  return result

class oneMany:
  def __init__(ctx, *args):
    ctx.nst = args

  def __getattr__(ctx, name):
    try:
      return getattr(ctx.nst, name)

    except AttributeError:
      one, = ctx.nst

      return getattr(one, name)

  def __getitem__(ctx, name):
    try:
      return ctx.nst[name]

    except KeyError:
      one, = ctx.nst

      return one[name]

  def __str__(ctx):
    one, = ctx.nst

    return str(one)

class manyMap:
  def __init__(ctx, *args, **kwds):
    ctx.nst = dict()

    for k, v in args:
      ctx.push(k, v)

    for k, v in kwds.iteritems():
      ctx.push(k, v)

  def push(ctx, name, *args):
    try:
      ctx.nst[name].extend(*args)

    except KeyError:
      ctx.nst[name] = oneMany(*args)

  def __getattr__(ctx, name):
    try:
      return getattr(ctx.nst, name)

    except AttributeError:
      try:
        return ctx.nst[name]

      except KeyError:
        raise AttributeError

  def __getitem__(ctx, name):
    try:
      return ctx.nst[name]

    except KeyError:
      try:
        return getattr(ctx.nst, name)

      except AttributeError:
        raise KeyError

urlencoded = lambda arg: manyMap(*(map(urllib.unquote_plus, pair.split('=', 1)) for pair in arg.split('&')))
