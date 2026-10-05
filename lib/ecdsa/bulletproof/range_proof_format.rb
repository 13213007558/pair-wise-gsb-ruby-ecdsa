# encoding: ASCII-8BIT

module ECDSA
  module Bulletproof
    # Binary encoding/decoding for single-value range proofs and commitments.
    #
    # All encodings are fixed width for a given curve and proof size:
    #
    # * one version byte ({VERSION_BYTE}),
    # * one byte holding the range bit length +n+,
    # * four SEC1 compressed points: +A+, +S+, +T1+, +T2+,
    # * five canonical fixed-width scalars: +t_hat+, +tau_x+, +mu+,
    #   +a_prime+, +s_prime+,
    # * two canonical scalars +t_l_k+, +t_r_k+ for every inner-product
    #   round (the round cross inner products), and
    # * +log2(n)+ compressed pairs +L_k+, +R_k+ for the inner-product
    #   argument.
    #
    # Decoding checks every item independently and raises
    # {ECDSA::Format::DecodeError} (a subclass of StandardError) on any
    # structural, curve, or range problem before any proof equation is
    # evaluated.
    module RangeProofFormat
      VERSION_BYTE = "\x01".b

      POINTS = %i[a s t1 t2].freeze
      SCALARS = %i[t_hat tau_x mu a_prime s_prime].freeze

      module_function

      def check_version!(string)
        if string.empty?
          raise Format::DecodeError, 'Range proof/commitment string is empty.'
        end
        if string.getbyte(0) != VERSION_BYTE.ord
          raise Format::DecodeError, 'Unknown range proof version byte: 0x%02x' % string.getbyte(0)
        end
      end

      # Encodes a {RangeProof}.  Does not encode the generators; the verifier
      # derives the same bases from the group and bit length.
      def encode(proof)
        parts = [VERSION_BYTE, [proof.bit_length].pack('C')]
        POINTS.each { |name| parts << Format::PointOctetString.encode(proof.public_send(name), compression: true) }
        SCALARS.each { |name| parts << Util.encode_scalar(proof.group, proof.public_send(name)) }
        proof.t_l.each { |scalar| parts << Util.encode_scalar(proof.group, scalar) }
        proof.t_r.each { |scalar| parts << Util.encode_scalar(proof.group, scalar) }
        proof.l_points.each { |point| parts << Format::PointOctetString.encode(point, compression: true) }
        proof.r_points.each { |point| parts << Format::PointOctetString.encode(point, compression: true) }
        parts.join
      end

      # Strict decode.  +expected_bit_length+ may be nil to accept any
      # supported bit length; otherwise the encoded +n+ must match.
      def decode(string, group, expected_bit_length)
        string = string.to_s.dup.force_encoding('BINARY')
        check_version!(string)
        check_length!(string, 2, 'bit length')

        bit_length = string.getbyte(1)
        RangeProof.check_supported_bit_length!(bit_length)
        if !expected_bit_length.nil? && bit_length != expected_bit_length
          raise Format::DecodeError,
                "Range proof is for #{bit_length} bits, expected #{expected_bit_length}."
        end

        offset = 2
        points = {}
        POINTS.each do |name|
          points[name] = decode_point!(string, offset, group)
          offset += 1 + group.byte_length
        end

        scalar_width = ECDSA.byte_length(group.order)
        scalars = {}
        SCALARS.each do |name|
          check_length!(string, offset + scalar_width, "scalar #{name}")
          scalars[name] = Util.decode_scalar(string.byteslice(offset, scalar_width), group)
          offset += scalar_width
        end

        rounds = bit_length.bit_length - 1
        t_l = []
        t_r = []
        rounds.times do
          check_length!(string, offset + scalar_width, 'inner-product scalar tL')
          t_l << Util.decode_scalar(string.byteslice(offset, scalar_width), group)
          offset += scalar_width
          check_length!(string, offset + scalar_width, 'inner-product scalar tR')
          t_r << Util.decode_scalar(string.byteslice(offset, scalar_width), group)
          offset += scalar_width
        end
        l_points = []
        r_points = []
        rounds.times do
          l_points << decode_point!(string, offset, group)
          offset += 1 + group.byte_length
          r_points << decode_point!(string, offset, group)
          offset += 1 + group.byte_length
        end

        if offset != string.length
          raise Format::DecodeError,
                "Range proof has #{string.length - offset} unexpected trailing bytes."
        end

        RangeProof.new(group: group, bit_length: bit_length, l_points: l_points,
                       r_points: r_points, t_l: t_l, t_r: t_r, **points, **scalars)
      end

      def decode_point!(string, offset, group)
        width = 1 + group.byte_length
        check_length!(string, offset + width, 'point')
        point = Format::PointOctetString.decode(string.byteslice(offset, width), group)
        check_subgroup_point!(point, group)
        point
      end

      # Raises {ECDSA::Format::DecodeError} if +point+ is outside the
      # prime-order subgroup.
      def check_subgroup_point!(point, group)
        if !group.include?(point)
          raise Format::DecodeError, 'Decoded point is not on the curve.'
        end
        if group.cofactor != 1 && point.multiply_by_scalar(group.order) != group.infinity
          raise Format::DecodeError, 'Decoded point is not in the prime-order subgroup.'
        end
      end

      def check_length!(string, needed, what)
        if string.length < needed
          raise Format::DecodeError,
                "Range proof string is too short: need #{needed} bytes for #{what}, got #{string.length}."
        end
      end
    end
  end
end
