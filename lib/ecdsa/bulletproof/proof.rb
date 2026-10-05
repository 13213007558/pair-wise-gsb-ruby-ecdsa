# encoding: ASCII-8BIT

module ECDSA
  module Bulletproof
    # The serialized proof is:
    # version and bit length, four commitments, five scalar openings, and the
    # left and right points from every inner-product reduction round.
    class Proof < Struct.new(
      :bit_length,
      :a_point, :s_point, :t1_point, :t2_point,
      :tau_x, :mu, :t_hat, :a_scalar, :b_scalar,
      :l_points, :r_points
    )
      VERSION = 1

      def self.decode(string, group)
        string = string.dup.force_encoding('BINARY')
        unless string.is_a?(String) && string.encoding == Encoding::BINARY
          raise Format::DecodeError, 'Proof must be a binary string.'
        end

        minimum_length = 5 + 4 * point_length(group) + 5 * scalar_length(group)
        raise Format::DecodeError, 'Proof is too short.' if string.bytesize < minimum_length
        raise Format::DecodeError, 'Unsupported proof version.' if string.ord != VERSION

        bit_length = decode_integer(string, 1, 4)
        unless SUPPORTED_BIT_LENGTHS.include?(bit_length)
          raise Format::DecodeError, 'Unsupported range bit length.'
        end

        rounds = ECDSA.bit_length(bit_length) - 1
        expected_length = minimum_length + 2 * rounds * point_length(group)
        check_length!(string, expected_length)

        offset = 5
        points = Array.new(4) do
          decode_point(string, offset, group).tap { offset += point_length(group) }
        end

        scalars = Array.new(5) do
          decode_scalar(string, offset, group).tap { offset += scalar_length(group) }
        end

        l_points = Array.new(rounds) do
          decode_point(string, offset, group).tap { offset += point_length(group) }
        end
        r_points = Array.new(rounds) do
          decode_point(string, offset, group).tap { offset += point_length(group) }
        end

        new(
          bit_length,
          *points,
          *scalars,
          l_points,
          r_points
        )
      end

      def self.coerce(proof, group)
        return proof if proof.is_a?(Proof)
        decode(proof, group)
      end

      def encode
        validate!
        rounds = r_points.size

        output = [VERSION, bit_length].pack('CN')
        [a_point, s_point, t1_point, t2_point].each { |point| output << encode_point(point) }
        [tau_x, mu, t_hat, a_scalar, b_scalar].each do |scalar|
          output << Format::IntegerOctetString.encode(scalar, scalar_byte_length)
        end
        l_points.each { |point| output << encode_point(point) }
        r_points.each { |point| output << encode_point(point) }
        output
      end

      alias_method :to_binary, :encode

      def validate!
        unless SUPPORTED_BIT_LENGTHS.include?(bit_length)
          raise ArgumentError, 'Unsupported range bit length.'
        end

        rounds = ECDSA.bit_length(bit_length) - 1
        unless l_points.is_a?(Array) && r_points.is_a?(Array) &&
               l_points.size == rounds && r_points.size == rounds
          raise ArgumentError, 'Proof has the wrong number of reduction points.'
        end

        points = [a_point, s_point, t1_point, t2_point] + l_points + r_points
        unless points.all? { |point| point.is_a?(Point) && point.group == group && group.valid_public_key?(point) }
          raise ArgumentError, 'Proof contains an invalid point.'
        end

        scalars = [tau_x, mu, t_hat, a_scalar, b_scalar]
        unless scalars.all? { |scalar| scalar.is_a?(Integer) && scalar >= 0 && scalar < group.order }
          raise ArgumentError, 'Proof contains an out-of-range scalar.'
        end
      end

      def group
        Group::Secp256k1
      end

      private

      def encode_point(point)
        unless point.is_a?(Point) && point.group == group && group.include?(point) && !point.infinity?
          raise ArgumentError, 'Proof contains an invalid point.'
        end
        Format::PointOctetString.encode(point, compression: true)
      end

      def scalar_byte_length
        self.class.send(:scalar_length, group)
      end

      def self.point_length(group)
        1 + group.byte_length
      end

      def self.scalar_length(group)
        ECDSA.byte_length(group.order)
      end

      def self.decode_integer(string, offset, length)
        Format::IntegerOctetString.decode(string.byteslice(offset, length))
      end

      def self.decode_point(string, offset, group)
        point = Format::PointOctetString.decode(
          string.byteslice(offset, point_length(group)), group
        )
        unless group.include?(point) && !point.infinity?
          raise Format::DecodeError, 'Proof point is not a valid public key.'
        end
        point
      end

      def self.decode_scalar(string, offset, group)
        scalar = Format::IntegerOctetString.decode(string.byteslice(offset, scalar_length(group)))
        unless scalar < group.order
          raise Format::DecodeError, 'Proof scalar is out of range.'
        end
        scalar
      end

      def self.check_length!(string, expected_length)
        return if string.bytesize == expected_length
        raise Format::DecodeError, 'Proof has an incorrect length.'
      end
    end
  end
end
