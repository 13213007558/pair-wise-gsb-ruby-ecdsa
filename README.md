# ECDSA gem for Ruby

[![Build Status](https://travis-ci.org/DavidEGrayson/ruby_ecdsa.svg?branch=master)](https://travis-ci.org/DavidEGrayson/ruby_ecdsa)

This gem implements the Elliptic Curve Digital Signature Algorithm (ECDSA)
almost entirely in pure Ruby.  It aims to be easier to use and easier to
understand than Ruby's
[OpenSSL EC support](http://www.ruby-doc.org/stdlib/libdoc/openssl/rdoc/OpenSSL/PKey/EC.html).
This gem does use OpenSSL but it only uses it to decode and encode ASN1 strings
for ECDSA signatures.  All cryptographic calculations are done in pure Ruby.

The main classes of this gem are `ECDSA::Group`, `ECDSA::Point`, and
`ECDSA::Signature`.  These classes operate on Ruby integers and do not deal at
all with binary formatting.  Encoding and decoding of binary formats is solely
handled by classes under the `ECDSA::Format` module.

You can enter your own curve parameters by instantiating a new `ECDSA::Group`
object or you can use a pre-existing group object such as
`ECDSA::Group::Secp256k1`.  The pre-existing groups can be seen in the
`lib/ecdsa/group` folder, and include all the curves defined in
[SEC2](http://www.secg.org/collateral/sec2_final.pdf) and
[NIST's Recommended Elliptic Curves for Federal Government Use](http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf).

This gem does not use any randomness; all the algorithms are deterministic.
In order to sign a message, you must generate a secure random number _k_
between 0 and the order of the group and pass it as an argument to `ECDSA.sign`.
You should take measures to ensure that you never use the same random number to
sign two different messages, or else it would be easy for someone to compute
your private key from those two signatures.

This gem is hosted at the [DavidEGrayson/ruby_ecdsa github repository](https://github.com/DavidEGrayson/ruby_ecdsa).

## Current limitations

- This gem only supports fields of integers modulo a prime number
  (_F<sub>p</sub>_).  ECDSA's characteristic 2 fields are not supported.
- The algorithms have not been optimized for speed, and will probably never be,
  because that would hinder the goal of helping people understand ECDSA.

This gem was not written by a cryptography expert and has not been carefully
checked.  It is provided "as is" and it is the user's responsibility to make
sure it will be suitable for the desired purpose.

## Installation

This library is distributed as a gem named [ecdsa](https://rubygems.org/gems/ecdsa)
at RubyGems.org.  To install it, run:

    gem install ecdsa

## Generating a private key

An ECDSA private key is a random number between 1 and the order of the group.
If you trust the `SecureRandom` class provided by your Ruby implementation, you
could generate a private key using this code:

```ruby
require 'ecdsa'
require 'securerandom'
group = ECDSA::Group::Secp256k1
private_key = 1 + SecureRandom.random_number(group.order - 1)
puts 'private key: %#x' % private_key
```

## Computing the public key for a private key

The public key consists of the coordinates of the point that is computed by
multiplying the generator point of the curve with the private key.
This is equivalent to adding the generator to itself `private_key` times.

```ruby
public_key = group.generator.multiply_by_scalar(private_key)
puts 'public key: '
puts '  x: %#x' % public_key.x
puts '  y: %#x' % public_key.y
```

The `public_key` object produced by the code above is an `ECDSA::Point` object.
    
## Encoding a public key as a binary string

Assuming that you have an `ECDSA::Point` object representing the public key,
you can convert it to the standard binary format defined in SEC1 with this code:

```ruby
public_key_string = ECDSA::Format::PointOctetString.encode(public_key, compression: true)
```

Setting the `compression` option to `true` decreases the size of the string by
almost 50% by only including one bit of the Y coordinate.  The other bits of the
Y coordinate are deduced from the X coordinate when the string is decoded.
    
This code returns a binary string.

## Decoding a public key from a binary string

To decode a SEC1 octet string, you can use the code below.  The `group` object
is assumed to be an `ECDSA::Group`.

```ruby
public_key = ECDSA::Format::PointOctetString.decode(public_key_string, group)
```

## Signing a message

This example shows how to generate a signature for a message.  In this example,
we will use SHA2 as our digest algorithm, but other algorithms can be used.

This example assumes that you trust the `SecureRandom` class in your Ruby
implementation to generate the temporary key (also known as `k`).  Beware that
if you accidentally sign two different messages with the same temporary key, it
is easy for someone to compute your private key from those two signatures and
then forge your signature.  Also, if someone can correctly guess the value of
the temporary key used for a signature, they can compute your private key from
that signature.

This example assumes that you have required the `ecdsa` gem, that you have an
`ECDSA::Group` object named `group`, and that you have the private key stored as
an integer in a variable named `private_key`.

```ruby
require 'digest/sha2'
message = 'ECDSA is cool.'
digest = Digest::SHA2.digest(message)
signature = nil
while signature.nil?
  temp_key = 1 + SecureRandom.random_number(group.order - 1)
  signature = ECDSA.sign(group, private_key, digest, temp_key)
end
puts 'signature: '
puts '  r: %#x' % signature.r
puts '  s: %#x' % signature.s
```
    
## Encoding a signature as a DER string

Signatures can be stored and transmitted as a [DER](http://en.wikipedia.org/wiki/X.690) string.
The code below encodes an `ECDSA::Signature` object as a binary DER string.

```ruby
signature_der_string = ECDSA::Format::SignatureDerString.encode(signature)
```

## Decoding a signature from a DER string

The code below decodes a binary DER string to produce an `ECDSA::Signature` object.

```ruby
signature = ECDSA::Format::SignatureDerString.decode(signature_der_string)
```
    
## Verifying a signature

The code below shows how to verify an ECDSA signature.  It assumes that you have
an `ECDSA::Point` object representing a public key, a string or integer
representing the digest of the signed messaged, and an `ECDSA::Signature` object
representing the signature.  The `valid_signature?` method returns `true` if the
signature is valid and `false` if it is not.

```ruby
valid = ECDSA.valid_signature?(public_key, digest, signature)
puts "valid: #{valid}"
```

## Schnorr adaptor signatures (secp256k1)

The `ECDSA::Schnorr` module implements
[BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
Schnorr signatures on secp256k1, and `ECDSA::Schnorr::Adaptor` builds
adaptor signatures on top of them.  An adaptor signature lets one party
publish a *pre-signature* that anyone can verify but that only becomes a
valid, ordinary BIP-340 signature once someone reveals the adaptor secret
_t_ of a public adaptor point _T = t*G_.  Once the final signature is
public, anyone holding the pre-signature can extract _t_ from the pair.

**Protocol variant.**  With _R = k*G_, _R' = R + T_, the BIP-340 challenge
_e = H(R'.x || P.x || m)_, and _q = +/-1_ the parity sign of _R'_ (see below):

    pre-sign:    s' = k + q*e*d          pre-verify:  s'*G == R + q*e*P
    adapt:       s  = q*(s' + t)         extract:      t  = q*s - s'

The final signature is _(R'.x, s)_ and verifies as an ordinary BIP-340
signature.

**Domain separation.**  All hashes are BIP-340 tagged hashes
(_SHA256(SHA256(tag) || SHA256(tag) || data)_); the challenge uses the tag
`BIP0340/challenge`, exactly as in BIP-340, so adapted signatures are
indistinguishable from ordinary BIP-340 signatures.  Messages must be
32-byte binary strings (e.g. a SHA-256 digest).

**Point parity conventions.**  Public keys are x-only: the even-y
representative is always used and secret keys are negated accordingly.
The nonce point _R'_ of the final signature must also have even y, so when
_R' = R + T_ has odd y the challenge term of the pre-signature is negated
(_q = -1_) and the adapted _s_ is negated modulo the group order.  The
parities of _R_ and _T_ themselves are unconstrained.

**Extraction safety.**  `extract_secret` re-checks the candidate secret
against the public adaptor point (_t*G == T_) and checks the final
signature's _r_ against _R + T_, so a wrong message, public key, adaptor
point, or signature can never produce a seemingly successful secret; it
raises `ExtractionError` instead.

```ruby
require 'digest/sha2'
group = ECDSA::Group::Secp256k1
message = Digest::SHA256.digest('pay me when the oracle reveals t')

# Signer creates a pre-signature locked to the adaptor point T.
presignature = ECDSA::Schnorr::Adaptor.presign(private_key, message, adaptor_point)

# Anyone can verify the pre-signature.
ECDSA::Schnorr::Adaptor.valid_presignature?(public_key, message, adaptor_point, presignature)

# Whoever learns t can adapt it into a final BIP-340 signature.
signature = ECDSA::Schnorr::Adaptor.adapt(presignature, t, adaptor_point: adaptor_point)
ECDSA::Schnorr.valid_signature?(public_key, message, signature)  # => true

# And anyone with both signatures can extract t.
t = ECDSA::Schnorr::Adaptor.extract_secret(presignature, signature, adaptor_point)
```

By default, nonces are drawn from `SecureRandom`.  Both
`ECDSA::Schnorr.sign` and `ECDSA::Schnorr::Adaptor.presign` accept an
explicit `nonce:` keyword, which exists mainly for deterministic test
vectors; never reuse a nonce for two different messages, or the secret
key can be computed from the resulting signatures.

## Supported platforms

This library should run on any Ruby interpreter that is compatible with Ruby 1.9.3.
It has been tested on JRuby 1.7.11 and MRI.

## Documentation

For complete documentation, see the [ECDSA page on RubyDoc.info](http://rubydoc.info/gems/ecdsa).
