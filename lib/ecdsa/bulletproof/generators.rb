require 'set'

module ECDSA
  module Bulletproof
    # Holds the independent generators needed by a range proof of a given
    # bit length on a given curve.
    #
    # Callers never pass their own bases to the range proof APIs: every
    # generator is derived deterministically from an explicit, labeled
    # domain-separation string using try-and-increment hash-to-curve
    # ({Util.hash_to_point}).  In particular, the Pedersen hiding base is
    # not a supplied multiple of the standard generator, so a caller cannot
    # accidentally pick +H = k*G+ with a known relative discrete logarithm
    # (which would destroy the hiding property).
    #
    # The domain string binds:
    #
    # * the protocol identifier +ECDSA::Bulletproof/Generators/v1+,
    # * the curve name, field prime, and scalar-field order, and
    # * the generator role label and its index.
    #
    # Derivation additionally rejects the standard generator itself, the
    # point at infinity, and any duplicate base.
    class Generators
      PROTOCOL_ID = 'ECDSA::Bulletproof/Generators/v1'

      PEDERSEN_H_ROLE = 'pedersen_h'
      IPA_Q_ROLE = 'ipa_q'
      IPA_G_ROLE = 'ipa_g'
      IPA_H_ROLE = 'ipa_h'

      # @return [ECDSA::Group]
      attr_reader :group

      # @return [Integer] supported range bit length (8, 16, or 32)
      attr_reader :bit_length

      # @return [ECDSA::Point] the Pedersen value base (the group generator).
      attr_reader :g

      # @return [ECDSA::Point] the Pedersen blinding base (hash derived).
      attr_reader :h

      # @return [ECDSA::Point] the inner-product argument blinding base.
      attr_reader :q

      # @return [Array<ECDSA::Point>] +G_i+ vector, index 0 is bit 0.
      attr_reader :g_vector

      # @return [Array<ECDSA::Point>] +H_i+ vector, index 0 is bit 0.
      attr_reader :h_vector

      def initialize(group, bit_length)
        @group = group
        @bit_length = bit_length
        @g = group.generator

        seen = Set.new([self.class.compressed(group.generator)])
        derive = lambda do |role, index|
          Generators.derive_point(group, role, index, seen)
        end

        @h = derive.call(PEDERSEN_H_ROLE, 0)
        @q = derive.call(IPA_Q_ROLE, 0)
        @g_vector = Array.new(bit_length) { |i| derive.call(IPA_G_ROLE, i) }
        @h_vector = Array.new(bit_length) { |i| derive.call(IPA_H_ROLE, i) }
      end

      # Returns a memoized {Generators} instance for the group and bit
      # length.  Derivation is deterministic so all callers share bases.
      def self.default(group, bit_length)
        @defaults ||= {}
        @defaults[[group.name, group.order, bit_length]] ||= new(group, bit_length)
      end

      def self.domain_separation_tag(group)
        Util.frame('proto', PROTOCOL_ID) +
          Util.frame('group', group.name) +
          Util.frame('p', Format::IntegerOctetString.encode(group.field.prime, group.byte_length)) +
          Util.frame('order', Util.encode_scalar(group, group.order))
      end

      # @api private
      def self.derive_point(group, role, index, seen)
        dst = domain_separation_tag(group)
        attempt = 0
        loop do
          label = attempt.zero? ? role : "#{role}##{attempt}"
          point = Util.hash_to_point(group, dst, label, index)
          compressed = compressed(point)
          break point if seen.add?(compressed)
          attempt += 1
          raise Error, 'Generator derivation failed.' if attempt > 1000
        end
      end

      def self.compressed(point)
        Format::PointOctetString.encode(point, compression: true)
      end
    end
  end
end
