require 'digest'
require 'securerandom'

module ECDSA
  # Schnorr adaptor signatures (a.k.a. "scriptless scripts" pre-signatures)
  # for the secp256k1 group.
  #
  # An adaptor signature lets one party publish a *pre-signature* that is
  # publicly verifiable but is not yet a valid signature.  Whoever knows the
  # secret `t` behind the public *adaptor point* `T = t * G` can later turn
  # the pre-signature into an ordinary Schnorr signature, and anyone who
  # sees both the pre-signature and the final signature can recover `t`.
  #
  # == Protocol variant
  #
  # This is the classic construction (Aumayr et al., "Generalized Channels
  # from Limited Blockchain Scripts and Adaptor Signatures") instantiated so
  # that the *final* signature is an ordinary BIP-340 Schnorr signature:
  #
  #   PreSign(x, T, m):
  #     choose nonce k,  R' = k * G,  R = R' + T   (retry while y(R) is odd)
  #     e = H_c(x(R) || x(P) || m)
  #     s' = k + e * x  (mod n)
  #     pre-signature = (R', s')
  #
  #   PreVerify(P, T, m, (R', s')):
  #     R = R' + T;  require R to have even y
  #     e = H_c(x(R) || x(P) || m)
  #     check  s' * G == R + e * P
  #
  #   Adapt((R', s'), t):
  #     s = s' + t  (mod n);  final signature = (x(R' + T), s)
  #
  #   Extract((R', s'), (r, s)):
  #     t = s - s'  (mod n);  MUST be re-checked against t * G == T
  #
  # == Domain separation
  #
  # All hashing uses BIP-340 style tagged hashes,
  # `tagged_hash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)`:
  #
  # * Challenge: tag "BIP0340/challenge", so adapted signatures verify with
  #   any standard BIP-340 verifier.
  # * Deterministic nonce derivation (only used when an explicit Integer
  #   nonce is given and the first candidate is unusable): tag
  #   "ECDSA::SchnorrAdaptor/nonce", a domain private to this gem.
  #
  # == Point parity conventions
  #
  # * Public keys are x-only, BIP-340 style: a public key is identified by
  #   its x coordinate and always lifted to the point with *even* y.  If the
  #   signer's key pair has an odd-y public key, the secret key is
  #   internally replaced by `n - x` during pre-signing.
  # * The combined nonce point `R = R' + T` of the final signature must have
  #   *even* y (the BIP-340 rule).  Pre-signing retries with fresh nonce
  #   candidates until this holds.
  # * The adaptor point `T` is a full curve point: both coordinates are
  #   significant, so `T` and `-T` are different adaptor points.  The
  #   infinity point is rejected as an adaptor point.
  #
  # == Nonce generation
  #
  # By default {presign} draws nonces from `SecureRandom`.  An explicit
  # Integer nonce may be passed (mainly for deterministic test vectors); it
  # is used as the first candidate, and if the resulting `R` has odd y,
  # further candidates are derived deterministically via the tagged hash
  # described above.  Never reuse a nonce for two different pre-signatures:
  # doing so leaks the secret key.
  module SchnorrAdaptor
    # Base class for all errors raised by this module.
    class Error < StandardError; end

    # Raised when an adaptor secret does not match the public adaptor point.
    class AdaptationError < Error; end

    # Raised when an extracted secret does not match the public adaptor
    # point.  {extract} never returns a "successful" secret that fails this
    # check: a wrong message, public key, or adaptor point anywhere in the
    # chain makes the extraction raise instead of returning garbage.
    class ExtractionError < Error; end

    # A Schnorr adaptor pre-signature.
    #
    # * +nonce_point+: the point `R' = k * G` (a full {ECDSA::Point}).
    # * +s+: the scalar `s' = k + e * x` (an Integer, `0 <= s' < n`).
    PreSignature = Struct.new(:nonce_point, :s)

    # An ordinary BIP-340 style Schnorr signature.
    #
    # * +r+: the x coordinate of the (even-y) nonce point `R`.
    # * +s+: the scalar `s = k + t + e * x` (mod n).
    Signature = Struct.new(:r, :s)

    # This module only supports secp256k1.
    GROUP = Group::Secp256k1

    # BIP-340 challenge tag: keeps final signatures compatible with
    # ordinary BIP-340 Schnorr verifiers.
    CHALLENGE_TAG = 'BIP0340/challenge'

    # Gem-private tag for deterministic nonce derivation.
    NONCE_TAG = 'ECDSA::SchnorrAdaptor/nonce'

    module_function

    # Creates a pre-signature for +message+ that can be completed by anyone
    # who knows the discrete logarithm of +adaptor_point+.
    #
    # @param secret_key (Integer) The signer's secret key, 1 <= x < n.
    # @param adaptor_point (Point) The public adaptor point T on secp256k1.
    # @param message (String) The message to sign (arbitrary byte string;
    #   use a 32-byte digest for strict BIP-340 interoperability).
    # @param nonce (Integer or nil) Optional explicit nonce (test vectors).
    #   When nil, a secure random nonce is generated.
    # @return (PreSignature)
    def presign(secret_key, adaptor_point, message, nonce: nil)
      secret_key = validate_secret_key(secret_key)
      adaptor_point = validate_point(adaptor_point, 'adaptor point')
      message = validate_message(message)
      validate_nonce(nonce) unless nonce.nil?

      order = GROUP.order
      public_key = GROUP.new_point(secret_key)
      # BIP-340 x-only convention: use the secret key whose public key has
      # an even y coordinate.
      secret_key = order - secret_key if public_key.y.odd?

      attempt = 0
      loop do
        k = nonce_candidate(secret_key, adaptor_point, message, nonce, attempt)
        attempt += 1
        next if k.zero?

        nonce_point = GROUP.new_point(k)
        combined = nonce_point + adaptor_point
        # BIP-340 parity convention: the final signature's nonce point
        # R = R' + T must have even y; otherwise try the next candidate.
        next if combined.infinity? || combined.y.odd?

        e = challenge(combined.x, public_key.x, message)
        s = (k + e * secret_key) % order
        return PreSignature.new(nonce_point, s)
      end
    end

    # Verifies a pre-signature against a public key, adaptor point, and
    # message.  Returns true or false; never raises for bad signatures.
    #
    # @param public_key (Point) The signer's public key.  Only its x
    #   coordinate is used (x-only, BIP-340 style); the y parity is ignored.
    # @param adaptor_point (Point) The public adaptor point T.
    # @param message (String)
    # @param pre_signature (PreSignature)
    # @return (true or false)
    def verify_presignature(public_key, adaptor_point, message, pre_signature)
      return false unless pre_signature.is_a?(PreSignature)
      return false unless pre_signature.s.is_a?(Integer)
      return false unless pre_signature.s >= 0 && pre_signature.s < GROUP.order

      public_key = normalize_public_key(public_key)
      nonce_point = normalize_full_point(pre_signature.nonce_point)
      adaptor_point = normalize_full_point(adaptor_point)
      return false unless public_key && nonce_point && adaptor_point
      return false unless message.is_a?(String)

      combined = nonce_point + adaptor_point
      return false if combined.infinity? || combined.y.odd?

      e = challenge(combined.x, public_key.x, message)
      lhs = GROUP.new_point(pre_signature.s)
      rhs = nonce_point + public_key.multiply_by_scalar(e)
      lhs == rhs
    rescue ArgumentError
      false
    end

    # Completes a pre-signature using the adaptor secret, producing an
    # ordinary BIP-340 Schnorr signature.
    #
    # The adaptor secret is checked against the public adaptor point before
    # anything is returned, so a wrong secret raises instead of silently
    # producing an invalid signature.
    #
    # @param pre_signature (PreSignature)
    # @param adaptor_secret (Integer) The secret t with t * G == adaptor_point.
    # @param adaptor_point (Point) The public adaptor point T.
    # @return (Signature)
    # @raise (AdaptationError) if adaptor_secret * G != adaptor_point
    def adapt(pre_signature, adaptor_secret, adaptor_point)
      adaptor_secret = validate_secret_key(adaptor_secret, 'adaptor secret')
      adaptor_point = validate_point(adaptor_point, 'adaptor point')
      unless GROUP.new_point(adaptor_secret) == adaptor_point
        raise AdaptationError, 'Adaptor secret does not match the adaptor point.'
      end

      combined = pre_signature.nonce_point + adaptor_point
      s = (pre_signature.s + adaptor_secret) % GROUP.order
      Signature.new(combined.x, s)
    end

    # Extracts the adaptor secret from a pre-signature and the corresponding
    # final signature.
    #
    # The candidate secret is always re-checked against the public adaptor
    # point: if the message, public key, or adaptor point used anywhere in
    # the chain was wrong, the check fails and {ExtractionError} is raised
    # instead of returning a meaningless "secret".
    #
    # @param pre_signature (PreSignature)
    # @param signature (Signature) The adapted final signature.
    # @param adaptor_point (Point) The public adaptor point T.
    # @return (Integer) The adaptor secret t with t * G == adaptor_point.
    # @raise (ExtractionError) if the extracted value does not match T.
    def extract(pre_signature, signature, adaptor_point)
      adaptor_point = validate_point(adaptor_point, 'adaptor point')
      candidate = (signature.s - pre_signature.s) % GROUP.order
      unless GROUP.new_point(candidate) == adaptor_point
        raise ExtractionError,
              'Extracted value does not match the adaptor point; ' \
              'the signature pair is inconsistent.'
      end
      candidate
    end

    # Verifies an ordinary BIP-340 style Schnorr signature.
    #
    # @param public_key (Point) x-only public key (y parity is ignored).
    # @param message (String)
    # @param signature (Signature)
    # @return (true or false)
    def verify(public_key, message, signature)
      return false unless signature.is_a?(Signature)
      return false unless signature.r.is_a?(Integer) && signature.s.is_a?(Integer)
      return false unless signature.r >= 0 && signature.r < GROUP.field.prime
      return false unless signature.s >= 0 && signature.s < GROUP.order
      return false unless message.is_a?(String)

      public_key = normalize_public_key(public_key)
      return false unless public_key

      e = challenge(signature.r, public_key.x, message)
      r_point = GROUP.new_point(signature.s) +
                public_key.multiply_by_scalar(GROUP.order - e)
      return false if r_point.infinity? || r_point.y.odd?
      r_point.x == signature.r
    rescue ArgumentError
      false
    end

    # BIP-340 style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
    # This method is NOT part of the public API of the ECDSA gem.
    def tagged_hash(tag, data)
      tag_hash = Digest::SHA256.digest(tag)
      Digest::SHA256.digest(tag_hash + tag_hash + data)
    end

    # The BIP-340 challenge hash, reduced modulo the group order.
    # This method is NOT part of the public API of the ECDSA gem.
    def challenge(r_x, public_key_x, message)
      bytes = tagged_hash(CHALLENGE_TAG, int32(r_x) + int32(public_key_x) + message)
      Format::IntegerOctetString.decode(bytes) % GROUP.order
    end

    # Encodes an integer as a 32-byte big-endian string.
    # This method is NOT part of the public API of the ECDSA gem.
    def int32(integer)
      Format::IntegerOctetString.encode(integer, 32)
    end

    def nonce_candidate(secret_key, adaptor_point, message, nonce, attempt)
      order = GROUP.order
      if nonce.nil?
        # Production default: secure random source.
        SecureRandom.random_number(order - 1) + 1
      elsif attempt.zero?
        nonce
      else
        # Deterministic re-derivation for explicit nonces whose first
        # candidate produced an odd-y combined nonce point.
        data = int32(secret_key) + int32(nonce) + compressed(adaptor_point) +
               message + int32(attempt)
        Format::IntegerOctetString.decode(tagged_hash(NONCE_TAG, data)) % order
      end
    end
    private_class_method :nonce_candidate

    def compressed(point)
      (point.y.even? ? "\x02" : "\x03") + int32(point.x)
    end
    private_class_method :compressed

    def validate_secret_key(value, name = 'secret key')
      unless value.is_a?(Integer) && value >= 1 && value < GROUP.order
        raise ArgumentError, "Invalid #{name}: must be an integer in 1...(group order)."
      end
      value
    end
    private_class_method :validate_secret_key

    def validate_point(point, name)
      unless point.is_a?(Point) && point.group == GROUP && !point.infinity? &&
             GROUP.include?(point)
        raise ArgumentError, "Invalid #{name}: must be a non-infinity point on secp256k1."
      end
      point
    end
    private_class_method :validate_point

    def validate_message(message)
      unless message.is_a?(String)
        raise ArgumentError, 'Invalid message: must be a String.'
      end
      message.dup.force_encoding(Encoding::BINARY)
    end
    private_class_method :validate_message

    def validate_nonce(nonce)
      unless nonce.is_a?(Integer) && nonce >= 1 && nonce < GROUP.order
        raise ArgumentError, 'Invalid nonce: must be an integer in 1...(group order).'
      end
    end
    private_class_method :validate_nonce

    # Lifts a public key to its even-y representative (x-only convention).
    # Returns nil if the input is not a valid secp256k1 point.
    def normalize_public_key(point)
      point = normalize_full_point(point)
      return nil unless point
      point.y.odd? ? point.negate : point
    end
    private_class_method :normalize_public_key

    def normalize_full_point(point)
      return nil unless point.is_a?(Point) && point.group == GROUP
      return nil if point.infinity? || !GROUP.include?(point)
      point
    end
    private_class_method :normalize_full_point
  end
end
