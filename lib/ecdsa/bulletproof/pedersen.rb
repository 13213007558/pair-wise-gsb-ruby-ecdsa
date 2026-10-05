# encoding: ASCII-8BIT

require 'securerandom'

module ECDSA
  module Bulletproof
    # Pedersen commitments using two independently derived generators.
    # Callers supply only the value and randomness; the bases cannot be
    # overridden through this interface.
    module Pedersen
      def self.commit(value, options = {})
        group = options.fetch(:group, Group::Secp256k1)
        validate_group!(group)
        validate_value!(value, group)

        randomness = options[:randomness]
        randomness ||= random_scalar(group, options[:rng])
        validate_randomness!(randomness, group)

        point = Generators.base.value_point.multiply_by_scalar(value) +
                Generators.base.blinding_point.multiply_by_scalar(randomness)
        [point, randomness]
      end

      def self.commitment_point(value, randomness, group = Group::Secp256k1)
        validate_group!(group)
        validate_value!(value, group)
        validate_randomness!(randomness, group)

        Generators.base.value_point.multiply_by_scalar(value) +
          Generators.base.blinding_point.multiply_by_scalar(randomness)
      end

      def self.random_scalar(group, rng = nil)
        rng ||= SecureRandom
        1 + rng.rand(group.order - 1)
      end

      def self.validate_group!(group)
        return if group == Group::Secp256k1
        raise ArgumentError, 'Bulletproof range proofs support only secp256k1.'
      end

      def self.validate_value!(value, group)
        unless value.is_a?(Integer) && value >= 0 && value < group.order
          raise ArgumentError, 'Pedersen value must be in 0...group order.'
        end
      end

      def self.validate_randomness!(randomness, group)
        unless randomness.is_a?(Integer) && randomness > 0 && randomness < group.order
          raise ArgumentError, 'Pedersen randomness must be in 1...group order.'
        end
      end
    end
  end
end
