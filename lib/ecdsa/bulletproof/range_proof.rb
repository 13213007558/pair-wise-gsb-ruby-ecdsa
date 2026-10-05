# encoding: ASCII-8BIT

module ECDSA
  module Bulletproof
    module RangeProof
      def self.prove(value, commitment_randomness, bit_length, options = {})
        group = options.fetch(:group, Group::Secp256k1)
        Pedersen.validate_group!(group)
        validate_bit_length!(bit_length)
        validate_proof_value!(value, bit_length)
        Pedersen.validate_randomness!(commitment_randomness, group)

        rng = options[:rng]
        generators = Generators.for_bit_length(group, bit_length)
        commitment = generators.value.multiply_by_scalar(value) +
                     generators.blinding.multiply_by_scalar(commitment_randomness)
        order = group.order
        scalars = PrimeField.new(order)

        transcript = Transcript.new(group, bit_length, commitment)
        alpha = Pedersen.random_scalar(group, rng)
        beta = Pedersen.random_scalar(group, rng)

        bits = bit_length.times.map { |i| (value >> i) & 1 }
        ones = Array.new(bit_length, 1)
        powers_of_two = bit_length.times.map { |i| 2 ** i }

        a_l = bits
        a_r = bit_length.times.map { |i| bits[i] - 1 }
        a_r_ring = a_r.map { |value| scalars.mod(value) }
        s_l = bit_length.times.map { Pedersen.random_scalar(group, rng) }
        s_r = bit_length.times.map { Pedersen.random_scalar(group, rng) }

        a_point = multivector(generators.g_vector, generators.h_vector, a_l, a_r_ring) +
                  generators.vector_blinding.multiply_by_scalar(alpha)
        s_point = multivector(generators.g_vector, generators.h_vector, s_l, s_r) +
                  generators.vector_blinding.multiply_by_scalar(beta)

        transcript.append_point('A', a_point)
        transcript.append_point('S', s_point)
        y = transcript.challenge('y')
        z = transcript.challenge('z')

        y_powers = powers(y, bit_length, order)
        y_inverse_powers = y_powers.map { |element| scalars.inverse(element) }
        z_squared = scalars.square(z)
        z_cubed = scalars.mod(z_squared * z)

        l0 = bit_length.times.map { |i| scalars.mod(a_l[i] - z) }
        l1 = s_l
        r0 = bit_length.times.map do |i|
          scalars.mod(y_powers[i] * (a_r_ring[i] + z) + z_squared * powers_of_two[i])
        end
        r1 = bit_length.times.map do |i|
          scalars.mod(y_powers[i] * (s_r[i] + z))
        end

        t0 = scalars.mod(inner_product(l0, r0, order))
        t1 = scalars.mod(
          inner_product(l1, r0, order) + inner_product(l0, r1, order)
        )
        t2 = inner_product(l1, r1, order)
        tau1 = Pedersen.random_scalar(group, rng)
        tau2 = Pedersen.random_scalar(group, rng)
        t1_point = generators.value.multiply_by_scalar(t1) +
                   generators.blinding.multiply_by_scalar(tau1)
        t2_point = generators.value.multiply_by_scalar(t2) +
                   generators.blinding.multiply_by_scalar(tau2)

        transcript.append_point('T1', t1_point)
        transcript.append_point('T2', t2_point)
        x = transcript.challenge('x')

        mu = scalars.mod(alpha + x * beta)
        tau_x = scalars.mod(commitment_randomness * z_squared + tau1 * x + tau2 * x * x)
        t_hat = scalars.mod(t0 + t1 * x + t2 * x * x)

        transcript.append_scalar('tau_x', tau_x)
        transcript.append_scalar('mu', mu)
        transcript.append_scalar('t_hat', t_hat)

        q = generators.generator.inner_product_point(transcript.state, generators)

        l_vector = bit_length.times.map { |i| scalars.mod(l0[i] + x * l1[i]) }
        r_vector = bit_length.times.map { |i| scalars.mod(r0[i] + x * r1[i]) }
        b_vector = r_vector

        h_basis = scaled_points(generators.h_vector, y_inverse_powers)
        folded_p = bitwise_multi_scalar(
          generators.g_vector.dup.concat(h_basis),
          l_vector.dup.concat(b_vector)
        )
        g_fold = generators.g_vector.dup
        h_fold = h_basis
        l_points = []
        r_points = []

        while l_vector.size > 1
          half = l_vector.size / 2
          l_lo = l_vector.first(half)
          l_hi = l_vector.last(half)
          r_lo = r_vector.first(half)
          r_hi = r_vector.last(half)
          b_lo = b_vector.first(half)
          b_hi = b_vector.last(half)
          g_lo = g_fold.first(half)
          g_hi = g_fold.last(half)
          h_lo = h_fold.first(half)
          h_hi = h_fold.last(half)

          l_point = multivector(g_hi, h_lo, l_lo, b_hi) +
                    q.multiply_by_scalar(inner_product(l_lo, r_hi, order))
          r_point = multivector(g_lo, h_hi, l_hi, b_lo) +
                    q.multiply_by_scalar(inner_product(l_hi, r_lo, order))
          l_points << l_point
          r_points << r_point

          transcript.append_point('L', l_point)
          transcript.append_point('R', r_point)
          u = transcript.challenge('u')
          u_inverse = scalars.inverse(u)

          l_vector = half.times.map do |i|
            scalars.mod(u * l_lo[i] + u_inverse * l_hi[i])
          end
          r_vector = half.times.map do |i|
            scalars.mod(u_inverse * r_lo[i] + u * r_hi[i])
          end
          b_vector = half.times.map do |i|
            scalars.mod(u_inverse * b_lo[i] + u * b_hi[i])
          end
          g_fold = half.times.map do |i|
            g_lo[i].multiply_by_scalar(u_inverse) + g_hi[i].multiply_by_scalar(u)
          end
          h_fold = half.times.map do |i|
            h_lo[i].multiply_by_scalar(u) + h_hi[i].multiply_by_scalar(u_inverse)
          end
          folded_p = l_point.multiply_by_scalar(scalars.square(u)) + folded_p +
                     r_point.multiply_by_scalar(scalars.square(u_inverse))
        end

        a_scalar = l_vector.first
        b_scalar = b_vector.first
        final_p = g_fold.first.multiply_by_scalar(a_scalar) +
                  h_fold.first.multiply_by_scalar(b_scalar) +
                  q.multiply_by_scalar(scalars.mod(a_scalar * b_scalar))
        unless folded_p + q.multiply_by_scalar(t_hat) == final_p
          raise RuntimeError, 'Inner-product proof construction failed.'
        end

        proof = Proof.new(
          bit_length,
          a_point, s_point, t1_point, t2_point,
          tau_x, mu, t_hat, a_scalar, b_scalar,
          l_points, r_points
        )
        proof.validate!
        proof
      end

      def self.valid?(commitment, proof, options = {})
        verify(commitment, proof, options)
        true
      rescue ArgumentError, Format::DecodeError, RuntimeError
        false
      end

      def self.verify(commitment, proof, options = {})
        group = options.fetch(:group, Group::Secp256k1)
        Pedersen.validate_group!(group)
        commitment = coerce_point(commitment, group)
        proof = Proof.coerce(proof, group)
        bit_length = proof.bit_length
        validate_bit_length!(bit_length)
        proof.validate!

        generators = Generators.for_bit_length(group, bit_length)
        order = group.order
        scalars = PrimeField.new(order)
        transcript = Transcript.new(group, bit_length, commitment)

        transcript.append_point('A', proof.a_point)
        transcript.append_point('S', proof.s_point)
        y = transcript.challenge('y')
        z = transcript.challenge('z')
        transcript.append_point('T1', proof.t1_point)
        transcript.append_point('T2', proof.t2_point)
        x = transcript.challenge('x')
        transcript.append_scalar('tau_x', proof.tau_x)
        transcript.append_scalar('mu', proof.mu)
        transcript.append_scalar('t_hat', proof.t_hat)
        q = generators.generator.inner_product_point(transcript.state, generators)

        y_powers = powers(y, bit_length, order)
        y_inverse_powers = y_powers.map { |element| scalars.inverse(element) }
        ones = Array.new(bit_length, 1)
        powers_of_two = bit_length.times.map { |i| 2 ** i }
        z_squared = scalars.square(z)
        z_cubed = scalars.mod(z_squared * z)
        x_squared = scalars.square(x)

        delta = scalars.mod(
          (z - z_squared) * inner_product(ones, y_powers, order) -
            z_cubed * inner_product(ones, powers_of_two, order)
        )
        t_check = proof.t1_point.multiply_by_scalar(x) +
                  bitwise_multi_scalar(
                    [
                      proof.t2_point,
                      commitment,
                      generators.value,
                      generators.value,
                      generators.blinding
                    ],
                    [
                      x_squared,
                      z_squared,
                      delta,
                      scalars.mod(-proof.t_hat),
                      scalars.mod(-proof.tau_x)
                    ]
                  )
        raise ArgumentError, 'Polynomial commitment check failed.' unless t_check == group.infinity

        h_coefficients = bit_length.times.map do |i|
          scalars.mod(
            z * (1 + x) +
              z_squared * powers_of_two[i] * y_inverse_powers[i]
          )
        end
        folded_p = bitwise_multi_scalar(
          [proof.a_point, proof.s_point, generators.vector_blinding] +
            generators.h_vector + generators.g_vector,
          [1, x, scalars.mod(-proof.mu)] +
            h_coefficients + Array.new(bit_length) { scalars.mod(-z) }
        )

        g_fold = generators.g_vector.dup
        h_fold = scaled_points(generators.h_vector, y_inverse_powers)

        proof.l_points.each_with_index do |l_point, i|
          r_point = proof.r_points[i]
          transcript.append_point('L', l_point)
          transcript.append_point('R', r_point)
          u = transcript.challenge('u')
          u_inverse = scalars.inverse(u)
          half = g_fold.size / 2

          g_lo = g_fold.first(half)
          g_hi = g_fold.last(half)
          h_lo = h_fold.first(half)
          h_hi = h_fold.last(half)
          g_fold = half.times.map do |j|
            g_lo[j].multiply_by_scalar(u_inverse) + g_hi[j].multiply_by_scalar(u)
          end
          h_fold = half.times.map do |j|
            h_lo[j].multiply_by_scalar(u) + h_hi[j].multiply_by_scalar(u_inverse)
          end
          folded_p = l_point.multiply_by_scalar(scalars.square(u)) + folded_p +
                     r_point.multiply_by_scalar(scalars.square(u_inverse))
        end

        final_p = g_fold.first.multiply_by_scalar(proof.a_scalar) +
                  h_fold.first.multiply_by_scalar(proof.b_scalar) +
                  q.multiply_by_scalar(scalars.mod(proof.a_scalar * proof.b_scalar))
        unless folded_p + q.multiply_by_scalar(proof.t_hat) == final_p
          raise ArgumentError, 'Inner-product range relation check failed.'
        end

        true
      end

      def self.validate_bit_length!(bit_length)
        return if SUPPORTED_BIT_LENGTHS.include?(bit_length)
        raise ArgumentError, 'Supported range bit lengths are 8, 16, and 32.'
      end

      private_class_method :validate_bit_length!

      def self.validate_proof_value!(value, bit_length)
        unless value.is_a?(Integer) && value >= 0 && value < (1 << bit_length)
          raise ArgumentError, "Value must be in 0...2^#{bit_length}."
        end
      end

      private_class_method :validate_proof_value!

      def self.coerce_point(point, group)
        point = Format::PointOctetString.decode(point, group) if point.is_a?(String)
        unless point.is_a?(Point) && point.group == group && group.include?(point) && !point.infinity?
          raise ArgumentError, 'Commitment is not a valid public key.'
        end
        point
      end

      private_class_method :coerce_point

      def self.multivector(g_points, h_points, l_scalars, r_scalars)
        first = g_points.first.multiply_by_scalar(l_scalars.first) +
                h_points.first.multiply_by_scalar(r_scalars.first)
        (1...g_points.size).reduce(first) do |sum, i|
          sum + g_points[i].multiply_by_scalar(l_scalars[i]) +
                h_points[i].multiply_by_scalar(r_scalars[i])
        end
      end

      private_class_method :multivector

      def self.bitwise_multi_scalar(points, scalars)
        order = points.first.group.order
        normalized = scalars.map { |scalar| scalar < 0 ? order + scalar : scalar }
        max_bits = ECDSA.bit_length(normalized.max || 0)
        result = points.first.group.infinity
        (max_bits - 1).downto(0) do |bit|
          result = result.double
          points.each_with_index do |point, i|
            result = result + point if normalized[i][bit] == 1
          end
        end
        result
      end

      private_class_method :bitwise_multi_scalar

      def self.scaled_points(points, scalars)
        order = points.first.group.order
        normalized = scalars.map do |scalar|
          scalar < 0 ? order + scalar : scalar
        end
        max_bits = ECDSA.bit_length(normalized.max || 0)
        results = Array.new(points.size) { points.first.group.infinity }

        (max_bits - 1).downto(0) do |bit|
          results.each_index { |i| results[i] = results[i].double }
          points.each_with_index do |point, i|
            results[i] = results[i] + point if normalized[i][bit] == 1
          end
        end

        results
      end

      private_class_method :scaled_points

      def self.powers(base, count, order)
        count.times.each_with_object([]) do |i, result|
          result << (i.zero? ? 1 : ((result.last * base) % order))
        end
      end

      private_class_method :powers

      def self.inner_product(left, right, order)
        total = left.each_with_index.reduce(0) do |sum, (value, i)|
          sum + value * right[i]
        end
        total % order
      end

      private_class_method :inner_product

      def self.delta(y_powers, ones, powers_of_two, z, order)
        z_squared = (z * z) % order
        z_cubed = (z_squared * z) % order
        y_sum = inner_product(ones, y_powers, order)
        weighted_sum = inner_product(ones, powers_of_two, order)
        ((z - z_squared) * y_sum - z_cubed * weighted_sum) % order
      end

      private_class_method :delta
    end
  end
end
