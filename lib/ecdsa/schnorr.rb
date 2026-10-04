require 'digest/sha2'
require 'securerandom'

module ECDSA
  # This module implements Schnorr signatures over secp256k1 using the
  # conventions of BIP-340:
  #
  # * Public keys are x-only: only the x coordinate of the point is
  #   committed to, and the point is always treated as its representative
  #   with an even y coordinate.  Secret keys are negated modulo the group
  #   order when needed so that the corresponding public key has even y.
  # * The nonce point R of a signature is likewise committed to by its x
  #   coordinate only, and the nonce is negated when needed so that R has
  #   even y.
  # * Domain separation uses BIP-340 tagged hashes:
  #   SHA256(SHA256(tag) || SHA256(tag) || data).  The signature challenge
  #   uses the tag BIP0340/challenge, exactly as in BIP-340, so signatures
  #   produced by this module (including adapted signatures produced by
  #   Schnorr::Adaptor) are valid BIP-340 signatures and vice versa.
  #
  # Messages must be 32-byte binary strings (typically a SHA-256 digest of
  # the actual message), matching the BIP-340 specification.
  #
  # By default, signing nonces are drawn from Ruby's SecureRandom.  Callers
  # may pass an explicit nonce (the nonce: keyword) which is mainly useful
  # for reproducible test vectors.  Never reuse a nonce for two different
  # messages: doing so reveals the secret key.
  module Schnorr
    # The group that all Schnorr operations in this module use.
    GROUP = Group::Secp256k1

    # Computes the BIP-340 tagged hash of data for the given tag.
    #
    # @param tag (String)
    # @param data (String) binary string
    # @return (String) 32-byte binary string
    def self.tagged_hash(tag, data)
      tag_hash = Digest::SHA256.digest(tag)
      Digest::SHA256.digest(tag_hash + tag_hash + data)
    end

    # Encodes an integer as a 32-byte big-endian binary string.
    #
    # @param integer (Integer)
    # @return (String)
    def self.bytes32(integer)
      Format::IntegerOctetString.encode(integer, 32)
    end

    # Checks that the message is a 32-byte binary string and returns it.
    #
    # @param message (String)
    # @return (String)
    def self.normalize_message(message)
      if !message.is_a?(String) || message.bytesize != 32
        raise ArgumentError, 'Message must be a 32-byte binary string (e.g. a SHA-256 digest).'
      end
      message
    end

    # Given a secret key, returns the pair [secret_key, public_key] where the
    # public key is the even-y representative of the public point and the
    # secret key is negated modulo the group order if necessary to match it
    # (the BIP-340 key convention).
    #
    # @param secret_key (Integer) a number in 1...(group order)
    # @return (Array) [Integer, Point]
    def self.normalize_secret_key(secret_key)
      if !secret_key.is_a?(Integer) || secret_key < 1 || secret_key >= GROUP.order
        raise ArgumentError, 'Secret key must be an integer in 1...(group order).'
      end
      point = GROUP.generator.multiply_by_scalar(secret_key)
      if point.y.odd?
        [GROUP.order - secret_key, point.negate]
      else
        [secret_key, point]
      end
    end

    # Returns the even-y representative of the given public key point, after
    # checking that it is a valid public key on secp256k1.  This is the point
    # that the x-only BIP-340 public key refers to.
    #
    # @param public_key (Point)
    # @return (Point)
    def self.normalize_public_key(public_key)
      if !public_key.is_a?(Point) || public_key.group != GROUP || !GROUP.valid_public_key?(public_key)
        raise ArgumentError, 'Public key must be a valid point on secp256k1.'
      end
      public_key.y.odd? ? public_key.negate : public_key
    end

    # Computes the BIP-340 signature challenge for the given values.
    #
    # @param r_x (Integer) x coordinate of the nonce point
    # @param public_x (Integer) x coordinate of the public key
    # @param message (String) 32-byte binary string
    # @return (Integer) the challenge, modulo the group order
    def self.challenge(r_x, public_x, message)
      hash = tagged_hash('BIP0340/challenge', bytes32(r_x) + bytes32(public_x) + message)
      Format::IntegerOctetString.decode(hash) % GROUP.order
    end

    # Generates a random nonce in 1...(group order) using SecureRandom.
    #
    # @return (Integer)
    def self.generate_nonce
      1 + SecureRandom.random_number(GROUP.order - 1)
    end

    # Produces a BIP-340 Schnorr signature.
    #
    # @param secret_key (Integer) the secret key, in 1...(group order)
    # @param message (String) a 32-byte binary string
    # @param nonce (Integer or nil) the secret nonce to use.  If nil, a nonce
    #   is generated with SecureRandom.  Never reuse a nonce for two
    #   different messages or the secret key can be computed from the
    #   signatures.
    # @return (Signature or nil) a Signature whose r is the x coordinate of
    #   the (even-y) nonce point and whose s is the signature scalar.
    #   Returns nil in the vanishingly unlikely case that s is zero and an
    #   explicit nonce was given; retry with a different nonce.
    def self.sign(secret_key, message, nonce: nil)
      message = normalize_message(message)
      secret_key, public_key = normalize_secret_key(secret_key)
      nonce ||= generate_nonce
      if !nonce.is_a?(Integer) || nonce < 1 || nonce >= GROUP.order
        raise ArgumentError, 'Nonce must be an integer in 1...(group order).'
      end

      r_point = GROUP.generator.multiply_by_scalar(nonce)
      if r_point.y.odd?
        nonce = GROUP.order - nonce
        r_point = r_point.negate
      end

      e = challenge(r_point.x, public_key.x, message)
      s = (nonce + e * secret_key) % GROUP.order
      return nil if s.zero?

      Signature.new(r_point.x, s)
    end

    # Verifies a BIP-340 Schnorr signature and returns true if it is valid.
    #
    # @param public_key (Point) the public key; its y parity is ignored and
    #   the even-y representative is used, per the x-only convention
    # @param message (String) a 32-byte binary string
    # @param signature (Signature) r is the x coordinate of the nonce point
    # @return (true or false)
    def self.valid_signature?(public_key, message, signature)
      check_signature!(public_key, message, signature)
    rescue InvalidSignatureError, ArgumentError
      false
    end

    # Verifies a BIP-340 Schnorr signature, raising InvalidSignatureError
    # if it is invalid and returning true otherwise.
    #
    # @param public_key (Point)
    # @param message (String) a 32-byte binary string
    # @param signature (Signature)
    # @return true
    def self.check_signature!(public_key, message, signature)
      public_key = normalize_public_key(public_key)
      message = normalize_message(message)

      if signature.r >= GROUP.field.prime
        raise InvalidSignatureError, 'Invalid signature: r is not less than the field prime.'
      end
      if signature.s >= GROUP.order
        raise InvalidSignatureError, 'Invalid signature: s is not less than the group order.'
      end

      e = challenge(signature.r, public_key.x, message)
      r_point = GROUP.generator.multiply_by_scalar(signature.s)
        .add_to_point(public_key.multiply_by_scalar(GROUP.order - e))

      raise InvalidSignatureError, 'Invalid signature: r is the point at infinity.' if r_point.infinity?
      raise InvalidSignatureError, 'Invalid signature: r has odd y.' if r_point.y.odd?
      raise InvalidSignatureError, 'Invalid signature: r does not match.' if r_point.x != signature.r

      true
    end
  end
end
