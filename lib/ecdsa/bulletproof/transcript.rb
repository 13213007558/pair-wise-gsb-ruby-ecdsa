require 'digest/sha2'

module ECDSA
  module Bulletproof
    # An append-only Fiat-Shamir transcript.
    #
    # Every item is appended with a unique string label and a
    # length-prefixed binary value (see {Util.frame}), so no two different
    # transcript histories can produce the same byte sequence.  Challenges
    # are non-zero scalars sampled with rejection sampling from a running
    # SHA-256 transcript state, and each sampled challenge is itself folded
    # back into the state.  A prover and a verifier that follow the same
    # sequence of appends necessarily derive the same challenges.
    class Transcript
      # @param domain (String) A domain-separation string that uniquely
      #   identifies the protocol, curve, and statement.
      def initialize(domain)
        @state = Digest::SHA256.digest(Util.frame('domain', domain))
        @challenge_counter = 0
      end

      # Appends a point using its SEC1 compressed encoding.
      def append_point(label, point)
        append(label, Format::PointOctetString.encode(point, compression: true))
      end

      # Appends a scalar using its canonical fixed-width encoding.
      def append_scalar(group, label, scalar)
        append(label, Util.encode_scalar(group, scalar))
      end

      # Appends a non-negative integer as +byte_length+ big-endian bytes.
      def append_integer(label, integer, byte_length = 8)
        append(label, Format::IntegerOctetString.encode(integer, byte_length))
      end

      # Appends an already-encoded binary value.
      def append_bytes(label, bytes)
        append(label, bytes.to_s.dup.force_encoding('BINARY'))
      end

      # Derives the next labeled challenge scalar.  The label and a counter
      # are both bound, so challenges drawn from the same transcript state
      # are independent.  The derived challenge is folded back in.
      def challenge(group, label)
        @challenge_counter += 1
        scalar = Util.challenge_scalar(group, @state, label, @challenge_counter)
        append_scalar(group, "#{label}.out", scalar)
        scalar
      end

      private

      def append(label, value)
        @state = Digest::SHA256.digest(@state + Util.frame(label, value))
      end
    end
  end
end
