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

The `ECDSA::SchnorrAdaptor` module implements Schnorr *adaptor signatures*
(also known as scriptless-script pre-signatures) for secp256k1.  One party
publishes a pre-signature that anyone can verify but that is not yet a valid
signature; once the secret behind a public *adaptor point* `T = t * G` is
revealed, the pre-signature can be adapted into an ordinary Schnorr
signature, and anyone holding both signatures can extract the secret `t`.

Protocol variant and conventions:

- The construction is the classic one (Aumayr et al.): the pre-signature is
  `(R', s')` with `R' = k * G` and `s' = k + e * x`, where the challenge
  `e` binds the *combined* nonce point `R = R' + T`.  Adapting adds the
  adaptor secret (`s = s' + t`), and extraction subtracts (`t = s - s'`).
- The final signature is an ordinary BIP-340 Schnorr signature: the
  challenge uses the BIP-340 tagged hash `BIP0340/challenge`, public keys
  are x-only (the even-y representative is used; if the signer's public key
  has odd y, the secret key is internally negated), and the combined nonce
  point `R = R' + T` is required to have even y (pre-signing retries the
  nonce until this holds).  Deterministic nonce re-derivation uses the
  gem-private tagged hash `ECDSA::SchnorrAdaptor/nonce` for domain
  separation.
- The adaptor point `T` is a full curve point: both coordinates are
  significant, and the infinity point is rejected.
- `extract` always re-checks the candidate secret against the public
  adaptor point (`t * G == T`) and raises
  `ECDSA::SchnorrAdaptor::ExtractionError` if it does not match, so a wrong
  message, public key, or adaptor point can never yield a "successful"
  bogus secret.  Likewise, `adapt` raises
  `ECDSA::SchnorrAdaptor::AdaptationError` if the adaptor secret does not
  match the adaptor point.

```ruby
require 'ecdsa'

group = ECDSA::Group::Secp256k1
adaptor_secret = 1 + SecureRandom.random_number(group.order - 1)
adaptor_point = group.new_point(adaptor_secret)  # T = t * G, shared publicly
message = Digest::SHA256.digest('send 1 coin to Alice')

# The signer pre-signs.  Nonces come from SecureRandom by default.
pre_signature = ECDSA::SchnorrAdaptor.presign(private_key, adaptor_point, message)

# Anyone can verify the pre-signature before it is witnessed.
valid = ECDSA::SchnorrAdaptor.verify_presignature(public_key, adaptor_point, message, pre_signature)

# Once the adaptor secret is known, adapt to a final BIP-340 Schnorr signature.
signature = ECDSA::SchnorrAdaptor.adapt(pre_signature, adaptor_secret, adaptor_point)
ECDSA::SchnorrAdaptor.verify(public_key, message, signature)  # => true

# Anyone who sees both signatures can recover the adaptor secret.
recovered = ECDSA::SchnorrAdaptor.extract(pre_signature, signature, adaptor_point)
recovered == adaptor_secret  # => true
```

By default `presign` draws its nonce from `SecureRandom`.  An explicit
integer nonce can be passed with the `nonce:` keyword to get deterministic
output (this is used for the test vectors in
`spec/schnorr_adaptor_spec.rb`); never reuse a nonce across pre-signatures,
as that leaks the secret key.

## Supported platforms

This library should run on any Ruby interpreter that is compatible with Ruby 1.9.3.
It has been tested on JRuby 1.7.11 and MRI.

## Documentation

For complete documentation, see the [ECDSA page on RubyDoc.info](http://rubydoc.info/gems/ecdsa).
