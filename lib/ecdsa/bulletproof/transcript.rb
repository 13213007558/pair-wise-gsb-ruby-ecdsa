# encoding: ASCII-8BIT

require 'digest/sha2'

module ECDSA
  module Bulletproof
    # A length-prefixed Fiat-Shamir transcript. Every item has a distinct label
    # and an explicit byte length, so unrelated fields cannot be concatenated
    # into ambiguous transcript input.
    class Transcript
      attr_reader :state

      def initialize(group, bit_length, commitment)
        @group = group
        @state = "\0" * 32
        append_bytes('domain', DOMAIN)
        append_integer('group-order', group.order, scalar_length)
        append_integer('bit-length', bit_length, 4)
        append_point('commitment', commitment)
      end

      def append_point(label, point)
        append_bytes(label, Format::PointOctetString.encode(point, compression: true))
      end

      def append_scalar(label, scalar)
        unless scalar.is_a?(Integer) && scalar >= 0 && scalar < @group.order
          raise ArgumentError, 'Transcript scalar is out of range.'
        end

        append_bytes(label, Format::IntegerOctetString.encode(scalar, scalar_length))
      end

      def append_integer(label, integer, length)
        unless integer.is_a?(Integer) && integer >= 0
          raise ArgumentError, 'Transcript integer is negative.'
        end

        append_bytes(label, Format::IntegerOctetString.encode(integer, length))
      end

      def challenge(label)
        candidate = 0
        counter = 0

        while candidate.zero?
          seed = frame(1, label, [counter].pack('N'))
          candidate = Format::IntegerOctetString.decode(Digest::SHA512.digest(seed)) % @group.order
          counter += 1
        end

        @state = Digest::SHA256.digest(seed + Format::IntegerOctetString.encode(candidate, scalar_length))
        candidate
      end

      private

      def append_bytes(label, bytes)
        bytes = bytes.dup.force_encoding('BINARY')
        label = label.encode('ASCII')
        raise ArgumentError, 'Transcript label is too long.' if label.bytesize > 255

        @state = Digest::SHA256.digest(frame(0, label, bytes))
      end

      def frame(kind, label, data)
        data = data.dup.force_encoding('BINARY')
        label = label.encode('ASCII')
        [@state, kind, label.bytesize].pack('a32CC') + label + [data.bytesize].pack('N') + data
      end

      def scalar_length
        ECDSA.byte_length(@group.order)
      end
    end
  end
end
