require 'digest/sha2'

module ECDSA
  module Bulletproof
    # Internal helpers for scalar-field arithmetic, fixed-width integer
    # encoding, hash-to-scalar sampling, and multi-scalar multiplication.
    # Everything in this module is deterministic given its inputs.
    module Util
      # SHA-256 output length in bytes.
      SHA256_LENGTH = 32

      module_function

      # Reduces an integer modulo the group order into the range [0, order).
      def mod_scalar(group, integer)
        integer % group.order
      end

      # Multiplies integers modulo the group order.
      def scalar_mul(group, *integers)
        field = scalar_field(group)
        integers.reduce(1) { |product, n| field.mod(product * n) }
      end

      # Computes the modular inverse of a non-zero scalar.
      # @raise [Error] if the scalar is zero.
      def scalar_inverse(group, scalar)
        scalar = mod_scalar(group, scalar)
        raise Error, 'Cannot invert zero scalar.' if scalar.zero?
        scalar_field(group).inverse(scalar)
      end

      def scalar_field(group)
        @scalar_fields ||= {}
        @scalar_fields[group] ||= PrimeField.new(group.order)
      end

      # Encodes a scalar as exactly +byte_length+ big-endian bytes.
      # @raise [Error] if the scalar is out of range.
      def encode_scalar(group, scalar)
        scalar = mod_scalar(group, scalar)
        Format::IntegerOctetString.encode(scalar, scalar_byte_length(group))
      end

      # Decodes a fixed-width big-endian string into a scalar, rejecting
      # values that are not reduced modulo the group order.
      def decode_scalar(string, group)
        expected = scalar_byte_length(group)
        if string.length != expected
          raise Format::DecodeError,
                "Expected scalar to be #{expected} bytes but it was #{string.length}."
        end
        scalar = Format::IntegerOctetString.decode(string)
        if scalar >= group.order
          raise Format::DecodeError, 'Decoded scalar is not reduced modulo the group order.'
        end
        scalar
      end

      def scalar_byte_length(group)
        ECDSA.byte_length(group.order)
      end

      # Uniformly samples a scalar in [1, order) from the given RNG.
      # The RNG must respond to +random_number(integer)+.
      def random_scalar(group, rng)
        raise ArgumentError, 'random: does not respond to random_number.' if !rng.respond_to?(:random_number)
        1 + rng.random_number(group.order - 1)
      end

      # Samples a challenge scalar in [1, order) using rejection sampling so
      # the result is uniform (no modular bias and never zero).
      #
      # +counter+ is mixed into the hash input, so the same transcript state
      # can safely yield several distinct, independently-labeled challenges.
      def challenge_scalar(group, transcript_state, label, counter)
        length = scalar_byte_length(group)
        limit = (1 << (8 * length)) - ((1 << (8 * length)) % group.order)
        digest = Digest::SHA256.new
        1000.times do |trial|
          input = transcript_state + frame(label, [counter, trial].pack('Q>2'))
          value = Format::IntegerOctetString.decode(digest.reset.update(input).digest)
          next if value >= limit
          scalar = value % group.order
          return scalar if !scalar.zero?
        end
        raise Error, 'Failed to sample a non-zero challenge scalar.'
      end

      # Length-prefixed framing: 1-byte label length, label, 4-byte value
      # length, value.  This makes transcripts unambiguous regardless of the
      # contents of the labels or values.
      def frame(label, value)
        label = label.to_s
        raise Error, 'Transcript label too long.' if label.length > 255
        [label.length].pack('C') + label + [value.length].pack('N') + value
      end

      # Deterministically derives a point from a domain-separated, labeled
      # input using try-and-increment with canonical (even-Y) encoding, as
      # described in Brier et al., "Efficient Public Key Encryption Based
      # on Arbitrary Cryptographic Functions Incorporating Keys".
      #
      # The caller supplies the complete domain-separation tag, which binds
      # the curve, the protocol, and the generator's role.
      def hash_to_point(group, dst, label, index)
        digest = Digest::SHA256
        base = dst.dup.force_encoding('BINARY') + frame(label, [index].pack('Q>'))
        byte_length = group.byte_length
        10_000.times do |counter|
          candidate_bytes = digest.digest(base + [counter].pack('Q>'))
          x = Format::IntegerOctetString.decode(candidate_bytes[0, byte_length])
          next if x.zero? || x >= group.field.prime
          ys = group.solve_for_y(x)
          next if ys.empty?
          y = ys.min # canonical: even Y
          point = group.new_point([x, y])
          next if !group.include?(point)
          return point
        end
        raise Error, 'hash_to_point failed to find a point.'
      end

      # Verifies that a decoded point lies in the prime-order subgroup.
      # On prime-order curves with cofactor 1 (e.g. secp256k1) an on-curve
      # check is sufficient; the expensive order multiplication is only
      # performed for curves with a larger cofactor.
      def check_subgroup!(point, group)
        raise InvalidProofError, 'Point is not on the curve.' if !group.include?(point)
        if group.cofactor != 1 && point.multiply_by_scalar(group.order) != group.infinity
          raise InvalidProofError, 'Point is not in the prime-order subgroup.'
        end
      end

      # Multi-scalar multiplication +sum(scalars[i] * points[i])+ using a
      # fixed-width window.  All points must belong to +group+.
      def multiscalar(group, scalars, points, window = 4)
        raise Error, 'scalars/points length mismatch.' if scalars.length != points.length
        return group.infinity if scalars.empty?

        tables = points.map do |point|
          raise Error, 'Point is not on the curve.' if !group.include?(point)
          table = [group.infinity]
          (1...(1 << window)).each { |digit| table << table[digit - 1].add_to_point(point) }
          table
        end

        window_count = (group.order.bit_length + window - 1) / window
        result = group.infinity
        (window_count - 1).downto(0) do |window_index|
          window.times { result = result.double } if window_index != window_count - 1
          scalars.each_with_index do |scalar, i|
            digit = (scalar >> (window_index * window)) & ((1 << window) - 1)
            result = result.add_to_point(tables[i][digit]) if !digit.zero?
          end
        end
        result
      end
    end
  end
end
