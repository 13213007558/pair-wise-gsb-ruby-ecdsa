module ECDSA
  module Schnorr
    # This module implements Schnorr adaptor signatures (also known as
    # "scriptless script" signatures) over secp256k1, built on top of the
    # BIP-340 conventions in {ECDSA::Schnorr}.
    #
    # Protocol variant
    # ----------------
    # An adaptor signature lets one party publish a *pre-signature* that
    # commits to a message and to a public adaptor point T = t*G.  Anyone
    # can verify the pre-signature, but only someone who knows the adaptor
    # secret t can turn it into a final, ordinary BIP-340 Schnorr signature;
    # and once the final signature is public, anyone holding the
    # pre-signature can extract t from the pair.  The equations are:
    #
    #   pre-sign:    R  = k*G,  R' = R + T
    #                e  = H(R'.x || P.x || m)   (BIP-340 challenge)
    #                s' = k + q*e*d             (mod n)
    #   pre-verify:  s'*G == R + q*e*P
    #   adapt:       s  = q*(s' + t)            (mod n)
    #   extract:     t  = q*s - s'              (mod n)
    #
    # where d and P = d*G follow the BIP-340 even-y key convention, the
    # final signature is (R'.x, s), and q is the parity sign of R':
    # q = +1 when R' has even y and q = -1 when R' has odd y.
    #
    # Point parity convention
    # -----------------------
    # The final signature must satisfy BIP-340, which commits to the nonce
    # point by its x coordinate only and requires the even-y representative.
    # Therefore, if R' = R + T has odd y, the challenge term of the
    # pre-signature is negated (s' = k - e*d), the adapted s is negated
    # modulo the group order (s = -(s' + t)), and extraction correspondingly
    # computes t = -(s + s').  The parity of R itself and of T is
    # unconstrained; only the parity of R' matters.
    #
    # Domain separation
    # -----------------
    # The challenge hash is the exact BIP-340 tagged hash with tag
    # "BIP0340/challenge", so an adapted signature is indistinguishable from
    # and verifiable as an ordinary BIP-340 signature.  No extra domain
    # separation is needed between pre-signatures and final signatures
    # because both share the same challenge by construction.
    #
    # Extraction safety
    # -----------------
    # {extract_secret} never trusts its inputs: the candidate secret is
    # checked against the public adaptor point (t*G == T) and the final
    # signature's r is checked against R + T before the secret is returned.
    # If the message, public key, adaptor point, or either signature is
    # wrong, extraction raises {ExtractionError} instead of returning a
    # plausible-looking but invalid secret.
    module Adaptor
      # Raised when the adaptor secret cannot be extracted from a
      # pre-signature / signature pair, for example because the inputs are
      # inconsistent with the public adaptor point.
      class ExtractionError < StandardError
      end

      # Raised when a pre-signature is invalid.
      class InvalidPreSignatureError < StandardError
      end

      # An adaptor pre-signature: the signer's nonce point R and the scalar
      # s' = k + e*d.  The adaptor point T is not stored here; it is a
      # parameter of the protocol and must be supplied to verification,
      # adaptation, and extraction.
      class PreSignature
        # @return (Point) the signer's nonce point R = k*G
        attr_reader :nonce_point

        # @return (Integer) the pre-signature scalar s'
        attr_reader :s

        def initialize(nonce_point, s)
          @nonce_point = nonce_point
          @s = s
        end
      end

      GROUP = Schnorr::GROUP

      # Produces an adaptor pre-signature.
      #
      # @param secret_key (Integer) the signer's secret key, in 1...(group order)
      # @param message (String) a 32-byte binary string
      # @param adaptor_point (Point) the public adaptor point T = t*G
      # @param nonce (Integer or nil) the secret nonce k.  If nil, a nonce is
      #   generated with SecureRandom.  Never reuse a nonce for two different
      #   messages or the secret key can be computed from the pre-signatures.
      # @return (PreSignature or nil) returns nil in the vanishingly unlikely
      #   case of a degenerate nonce (R + T is infinity or s' is zero) when
      #   an explicit nonce was given; retry with a different nonce.
      def self.presign(secret_key, message, adaptor_point, nonce: nil)
        message = Schnorr.normalize_message(message)
        adaptor_point = normalize_adaptor_point(adaptor_point)
        secret_key, public_key = Schnorr.normalize_secret_key(secret_key)
        nonce ||= Schnorr.generate_nonce
        if !nonce.is_a?(Integer) || nonce < 1 || nonce >= GROUP.order
          raise ArgumentError, 'Nonce must be an integer in 1...(group order).'
        end

        nonce_point = GROUP.generator.multiply_by_scalar(nonce)
        adapted_nonce_point = nonce_point.add_to_point(adaptor_point)
        return nil if adapted_nonce_point.infinity?

        e = Schnorr.challenge(adapted_nonce_point.x, public_key.x, message)
        e = GROUP.order - e if adapted_nonce_point.y.odd?
        s = (nonce + e * secret_key) % GROUP.order
        return nil if s.zero?

        PreSignature.new(nonce_point, s)
      end

      # Verifies an adaptor pre-signature and returns true if it is valid.
      #
      # @param public_key (Point) the signer's public key
      # @param message (String) a 32-byte binary string
      # @param adaptor_point (Point) the public adaptor point T
      # @param presignature (PreSignature)
      # @return (true or false)
      def self.valid_presignature?(public_key, message, adaptor_point, presignature)
        check_presignature!(public_key, message, adaptor_point, presignature)
      rescue InvalidPreSignatureError, ArgumentError
        false
      end

      # Verifies an adaptor pre-signature, raising {InvalidPreSignatureError}
      # if it is invalid and returning true otherwise.
      #
      # @param public_key (Point) the signer's public key
      # @param message (String) a 32-byte binary string
      # @param adaptor_point (Point) the public adaptor point T
      # @param presignature (PreSignature)
      # @return true
      def self.check_presignature!(public_key, message, adaptor_point, presignature)
        public_key = Schnorr.normalize_public_key(public_key)
        message = Schnorr.normalize_message(message)
        adaptor_point = normalize_adaptor_point(adaptor_point)
        nonce_point = normalize_nonce_point(presignature.nonce_point)

        if !presignature.s.is_a?(Integer) || presignature.s < 1 || presignature.s >= GROUP.order
          raise InvalidPreSignatureError, 'Invalid pre-signature: s is not in 1...(group order).'
        end

        adapted_nonce_point = nonce_point.add_to_point(adaptor_point)
        if adapted_nonce_point.infinity?
          raise InvalidPreSignatureError, 'Invalid pre-signature: R + T is the point at infinity.'
        end

        e = Schnorr.challenge(adapted_nonce_point.x, public_key.x, message)
        e = GROUP.order - e if adapted_nonce_point.y.odd?
        left = GROUP.generator.multiply_by_scalar(presignature.s)
        right = nonce_point.add_to_point(public_key.multiply_by_scalar(e))
        if left != right
          raise InvalidPreSignatureError, 'Invalid pre-signature: s*G does not equal R + e*P.'
        end

        true
      end

      # Adapts a pre-signature into a final, ordinary BIP-340 Schnorr
      # signature using the adaptor secret.
      #
      # @param presignature (PreSignature)
      # @param adaptor_secret (Integer) the secret t such that T = t*G
      # @param adaptor_point (Point or nil) if given, the adaptor secret is
      #   checked against this public point before anything else happens,
      #   and an ArgumentError is raised on mismatch
      # @return (Signature or nil) the final signature (R'.x, s), or nil in
      #   the vanishingly unlikely case that s is zero
      def self.adapt(presignature, adaptor_secret, adaptor_point: nil)
        if !adaptor_secret.is_a?(Integer) || adaptor_secret < 1 || adaptor_secret >= GROUP.order
          raise ArgumentError, 'Adaptor secret must be an integer in 1...(group order).'
        end
        computed_point = GROUP.generator.multiply_by_scalar(adaptor_secret)
        if adaptor_point && computed_point != normalize_adaptor_point(adaptor_point)
          raise ArgumentError, 'Adaptor secret does not match the adaptor point.'
        end

        adapted_nonce_point = presignature.nonce_point.add_to_point(computed_point)
        s = (presignature.s + adaptor_secret) % GROUP.order
        s = GROUP.order - s if adapted_nonce_point.y.odd? && !s.zero?
        return nil if s.zero?

        Signature.new(adapted_nonce_point.x, s)
      end

      # Extracts the adaptor secret from a pre-signature and the final
      # signature that was adapted from it.
      #
      # The candidate secret is always re-checked against the public adaptor
      # point, and the final signature's r is checked against R + T, so
      # inconsistent inputs (wrong message, public key, adaptor point, or
      # signatures) can never yield a seemingly successful result.
      #
      # @param presignature (PreSignature)
      # @param signature (Signature) the final BIP-340 signature
      # @param adaptor_point (Point) the public adaptor point T
      # @return (Integer) the adaptor secret t such that T = t*G
      # @raise (ExtractionError) if the inputs are inconsistent
      def self.extract_secret(presignature, signature, adaptor_point)
        adaptor_point = normalize_adaptor_point(adaptor_point)
        nonce_point = normalize_nonce_point(presignature.nonce_point)

        adapted_nonce_point = nonce_point.add_to_point(adaptor_point)
        if adapted_nonce_point.infinity?
          raise ExtractionError, 'Cannot extract secret: R + T is the point at infinity.'
        end
        if signature.r != adapted_nonce_point.x
          raise ExtractionError, 'Cannot extract secret: signature r does not match R + T.'
        end
        if !signature.s.is_a?(Integer) || signature.s < 1 || signature.s >= GROUP.order
          raise ExtractionError, 'Cannot extract secret: signature s is not in 1...(group order).'
        end

        secret = if adapted_nonce_point.y.even?
          (signature.s - presignature.s) % GROUP.order
        else
          (GROUP.order - signature.s - presignature.s) % GROUP.order
        end

        if secret.zero? || GROUP.generator.multiply_by_scalar(secret) != adaptor_point
          raise ExtractionError, 'Cannot extract secret: candidate secret does not match the adaptor point.'
        end

        secret
      end

      # Validates a public key or adaptor point and returns it.
      def self.normalize_key(point, name)
        if !point.is_a?(Point) || point.group != GROUP || !GROUP.valid_public_key?(point)
          raise ArgumentError, '%s must be a valid, non-infinity point on secp256k1.' % name
        end
        point
      end
      private_class_method :normalize_key

      def self.normalize_adaptor_point(point)
        normalize_key(point, 'Adaptor point')
      end
      private_class_method :normalize_adaptor_point

      def self.normalize_nonce_point(point)
        normalize_key(point, 'Pre-signature nonce point')
      end
      private_class_method :normalize_nonce_point
    end
  end
end
