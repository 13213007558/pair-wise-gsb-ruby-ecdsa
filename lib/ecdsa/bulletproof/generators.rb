# encoding: ASCII-8BIT

require 'digest/sha2'

module ECDSA
  module Bulletproof
    class Generators
      Set = Struct.new(:generator, :value, :blinding, :vector_blinding, :g_vector, :h_vector)
      MAX_BIT_LENGTH = 32

      def self.base
        @base ||= new(Group::Secp256k1)
      end

      def self.for_bit_length(group, bit_length)
        raise ArgumentError, 'Only secp256k1 is supported.' unless group == Group::Secp256k1
        generators = base
        generators.ensure_count(bit_length)
        Set.new(
          generators,
          generators.value_point,
          generators.blinding_point,
          generators.vector_blinding_point,
          generators.g_points.first(bit_length),
          generators.h_points.first(bit_length)
        )
      end

      attr_reader :value_point, :blinding_point, :vector_blinding_point, :g_points, :h_points

      def initialize(group)
        raise ArgumentError, 'Only secp256k1 is supported.' unless group == Group::Secp256k1

        @group = group
        @used_points = []
        @g_points = []
        @h_points = []
        @forbidden_points = [@group.generator]
        @value_point = derive('pedersen-value', 0, '')
        @blinding_point = derive('pedersen-blinding', 0, '')
        @vector_blinding_point = derive('vector-blinding', 0, '')
      end

      def ensure_count(count)
        while @g_points.size < count
          index = @g_points.size
          @g_points << derive('range-g', index, '')
        end

        while @h_points.size < count
          index = @h_points.size
          @h_points << derive('range-h', index, '')
        end
      end

      def inner_product_point(transcript_state, set)
        existing = [set.value, set.blinding] + set.g_vector + set.h_vector + @used_points
        point = derive('inner-product-q', 0, transcript_state, existing.dup)
        point
      end

      private

      def derive(purpose, index, data, existing = @used_points)
        counter = 0

        loop do
          begin
            point = candidate(purpose, index, data, counter, existing)
            valid = @group.include?(point) && !point.infinity? &&
                    !forbidden?(point, existing)
            if valid
              existing << point unless existing.equal?(@used_points)
              @used_points << point if existing.equal?(@used_points)
              @forbidden_points << point if existing.equal?(@used_points)
            end
            return point if valid
          rescue RuntimeError
            # Retry hashes that map outside the field or to a non-residue.
          end
          counter += 1
        end
      end

      def candidate(purpose, index, data, counter, existing)
        message = [DOMAIN.bytesize, DOMAIN, purpose.bytesize, purpose].pack('Ca*Ca*')
        message << [index, data.bytesize, counter].pack('NNN')
        message << data.dup.force_encoding('BINARY')

        x = Digest::SHA256.digest(message).bytes.reduce(0) do |value, byte|
          (value << 8 | byte) % @group.field.prime
        end
        x = (x + 1) % @group.field.prime
        field = @group.field
        right_side = field.mod(x * x * x + 7)
        y = field.power(right_side, (field.prime + 1) / 4)
        raise RuntimeError, 'Non-residue hash-to-curve candidate.' unless field.mod(y * y) == right_side
        y = field.mod(-y) if y.odd?
        point = @group.new_point([x, y])
        raise RuntimeError, 'Generator collision.' if forbidden?(point, existing)
        point
      end

      def forbidden?(point, existing)
        @forbidden_points.include?(point) || existing.include?(point)
      end

      private :forbidden?
    end
  end
end
