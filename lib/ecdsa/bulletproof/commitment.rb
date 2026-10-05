module ECDSA
  module Bulletproof
    # A Pedersen commitment +V = v*G + gamma*H+ to a non-negative integer
    # value +v+.  The commitment is perfectly hiding if +gamma+ is sampled
    # uniformly from the scalar field, and computationally binding under
    # the discrete-logarithm assumption relative to the
    # {Generators#g}/{Generators#h} bases.
    class Commitment
      # @return [ECDSA::Group]
      attr_reader :group

      # @return [ECDSA::Point] the commitment point +V+
      attr_reader :point

      # @api private
      def initialize(group, point)
        @group = group
        @point = point
      end

      # Encodes the commitment point as a version byte followed by a
      # SEC1 compressed point.
      # @return [String] binary (ASCII-8BIT) string
      def encode
        RangeProofFormat::VERSION_BYTE +
          Format::PointOctetString.encode(point, compression: true)
      end

      # Decodes a {Commitment} produced by {#encode}, rejecting points that
      # are not on the curve or (on non-prime-order curves) outside the
      # prime-order subgroup.
      # @param string [String]
      # @param group [ECDSA::Group]
      # @return [Commitment]
      def self.decode(string, group)
        string = string.to_s.dup.force_encoding('BINARY')
        RangeProofFormat.check_version!(string)
        point = Format::PointOctetString.decode(string.byteslice(1..-1), group)
        RangeProofFormat.check_subgroup_point!(point, group)
        new(group, point)
      end

      def ==(other)
        other.is_a?(Commitment) && other.group == group && other.point == point
      end
      alias eql? ==

      def hash
        [group, point].hash
      end

      def inspect
        "#<#{self.class}: #{point.inspect}>"
      end
    end
  end
end
