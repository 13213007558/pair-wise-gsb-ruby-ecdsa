require 'securerandom'

module ECDSA
  module Bulletproof
    # A Bulletproof single-value range proof.
    #
    # Attests that a Pedersen-committed value v lies in [0, 2^n) using the
    # optimized single-value Bulletproofs protocol (Buenz et al., 2018).
    #
    # Fiat-Shamir transcript ordering: the y challenge (and the y-scaled H
    # bases used for the inner-product argument) is derived from V alone;
    # A and S are then built over those same scaled bases and appended to
    # the transcript before z is derived.  This keeps the bases used by the
    # commitments and the inner-product argument identical, so the verifier
    # reconstructs every term without witness information.
    class RangeProof
      SUPPORTED_BIT_LENGTHS = [8, 16, 32].freeze
      PROTOCOL_DOMAIN = 'ECDSA::Bulletproof/RangeProof/v1'.freeze

      attr_reader :group, :bit_length, :a, :s, :t1, :t2,
                  :t_hat, :tau_x, :mu, :a_prime, :s_prime,
                  :l_points, :r_points, :t_l, :t_r

      def initialize(group:, bit_length:, a:, s:, t1:, t2:, t_hat:, tau_x:, mu:,
                     a_prime:, s_prime:, l_points:, r_points:, t_l:, t_r:)
        @group, @bit_length = group, bit_length
        @a, @s, @t1, @t2 = a, s, t1, t2
        @t_hat, @tau_x, @mu = t_hat, tau_x, mu
        @a_prime, @s_prime = a_prime, s_prime
        @l_points, @r_points = l_points, r_points
        @t_l, @t_r = t_l, t_r
      end

      def self.check_supported_bit_length!(bit_length)
        unless SUPPORTED_BIT_LENGTHS.include?(bit_length)
          raise ArgumentError,
                "Unsupported range bit length #{bit_length}; supported: #{SUPPORTED_BIT_LENGTHS.join(', ')}."
        end
      end

      def self.prove(group:, bit_length:, value:, blinding:, random: nil,
                     generators: nil)
        check_supported_bit_length!(bit_length)
        validate_value!(value, bit_length)
        validate_blinding!(group, blinding)
        rng = random || SecureRandom
        raise ArgumentError, 'random: does not respond to random_number(int)' unless rng.respond_to?(:random_number)
        gens = generators || Generators.default(group, bit_length)
        n = bit_length
        field = Util.scalar_field(group)
        mod = ->(integer) { field.mod(integer) }

        a_l = Array.new(n) { |i| (value >> i) & 1 }
        a_r = a_l.map { |bit| bit - 1 }
        alpha = Util.random_scalar(group, rng)
        s_l = Array.new(n) { Util.random_scalar(group, rng) }
        s_r = Array.new(n) { Util.random_scalar(group, rng) }
        rho = Util.random_scalar(group, rng)

        v_point = value_commitment(group, gens, value, blinding)

        transcript = transcript_after_v(group, n, v_point.point)
        y = transcript.challenge(group, 'y')
        y_vec = powers(y, n, mod)
        # The inner-product H bases are scaled by y; A and S use the SAME
        # scaled bases so no witness-dependent correction is ever needed.
        h_bases = scaled_h(gens, y_vec, mod)

        a_point = Util.multiscalar(group, a_l + a_r + [alpha],
                                   gens.g_vector + h_bases + [gens.h])
        s_point = Util.multiscalar(group, s_l + s_r + [rho],
                                   gens.g_vector + h_bases + [gens.h])
        transcript.append_point('A', a_point)
        transcript.append_point('S', s_point)
        z = transcript.challenge(group, 'z')

        yn_sum = geometric_sum(y, n, mod)
        z2 = mod.call(z * z)
        z3 = mod.call(z2 * z)

        # Witness polynomials over the y-scaled H bases H*_i = y^i H_i.
        # Because the bases already carry y^i, the witness coefficients do
        # NOT carry an extra y^i factor:
        #   l(X) = a_L - z + s_L X,
        #   r(X) = (a_R + z) + z^2 y^{-n} 2^n + s_R X.
        l0 = a_l.map { |bit| mod.call(bit - z) }
        l1 = s_l
        y_inv = y_vec.map { |yi| Util.scalar_inverse(group, yi) }
        r0 = Array.new(n) do |i|
          mod.call(a_r[i] + z * y_inv[i] + z2 * y_inv[i] * (1 << i))
        end
        r1 = s_r

        t1 = mod.call(inner(l0, r1, mod) + inner(l1, r0, mod))
        t2 = inner(l1, r1, mod)
        tau1 = Util.random_scalar(group, rng)
        tau2 = Util.random_scalar(group, rng)
        t1_point = gens.g * t1 + gens.h * tau1
        t2_point = gens.g * t2 + gens.h * tau2

        transcript.append_point('T1', t1_point)
        transcript.append_point('T2', t2_point)
        x = transcript.challenge(group, 'x')

        l = l0.zip(l1).map { |p, q| mod.call(p + q * x) }
        r = r0.zip(r1).map { |p, q| mod.call(p + q * x) }

        t_hat = inner(l, r, mod)
        x2 = mod.call(x * x)
        tau_x = mod.call(tau2 * x2 + tau1 * x + z2 * blinding)
        mu = mod.call(alpha + rho * x)

        transcript.append_scalar(group, 't_hat', t_hat)
        transcript.append_scalar(group, 'tau_x', tau_x)
        transcript.append_scalar(group, 'mu', mu)

        delta = delta(yn_sum, z, z2, z3, n, mod)
        t0 = mod.call(z2 * value + delta)
        raise Error, 'Internal error: t polynomial mismatch.' if mod.call(t0 + t1 * x + t2 * x2 - t_hat) != 0

        ipa = InnerProductArgument.prove(
          group: group, transcript: transcript, generators: gens,
          g_vector: gens.g_vector, h_vector: h_bases,
          l_vector: l, r_vector: r
        )

        new(group: group, bit_length: n, a: a_point, s: s_point,
            t1: t1_point, t2: t2_point, t_hat: t_hat, tau_x: tau_x, mu: mu,
            a_prime: ipa[:a_prime], s_prime: ipa[:s_prime],
            l_points: ipa[:l_points], r_points: ipa[:r_points],
            t_l: ipa[:t_l], t_r: ipa[:t_r])
      end

      def self.valid?(commitment, proof, bit_length:, group: ECDSA::Group::Secp256k1,
                        generators: nil)
        check_range_proof!(group, bit_length, commitment, proof, generators)
        true
      rescue Error, Format::DecodeError
        false
      end

      def self.check_range_proof!(group, bit_length, commitment, proof, generators = nil)
        check_supported_bit_length!(bit_length)
        commitment = coerce_commitment(group, commitment)
        proof = coerce_proof(group, bit_length, proof)
        gens = generators || Generators.default(group, bit_length)
        verify!(group, bit_length, commitment, proof, gens)
        true
      end

      def self.verify!(commitment, proof, bit_length:, group: ECDSA::Group::Secp256k1,
                       generators: nil)
        check_range_proof!(group, bit_length, commitment, proof, generators)
      end

      def self.coerce_commitment(group, commitment)
        return commitment if commitment.is_a?(Commitment)
        Commitment.decode(commitment, group)
      end

      def self.coerce_proof(group, bit_length, proof)
        return proof if proof.is_a?(RangeProof)
        RangeProofFormat.decode(proof, group, bit_length)
      end

      def self.commitment(group:, value:, blinding:, bit_length:, generators: nil)
        check_supported_bit_length!(bit_length)
        validate_value!(value, bit_length)
        validate_blinding!(group, blinding)
        gens = generators || Generators.default(group, bit_length)
        value_commitment(group, gens, value, blinding)
      end

      def encode
        RangeProofFormat.encode(self)
      end

      def self.decode(string, group, expected_bit_length = nil)
        RangeProofFormat.decode(string, group, expected_bit_length)
      end

      def inspect
        "#<#{self.class}: n=#{bit_length} bytes>"
      end

      def self.validate_value!(value, bit_length)
        if !value.is_a?(Integer) || value < 0
          raise ArgumentError, 'value must be a non-negative integer.'
        end
        if value >= (1 << bit_length)
          raise ArgumentError, "value #{value} is out of range for #{bit_length}-bit proof."
        end
      end

      def self.validate_blinding!(group, blinding)
        if !blinding.is_a?(Integer) || blinding <= 0 || blinding >= group.order
          raise ArgumentError, 'blinding must be a non-zero scalar in [1, order).'
        end
      end

      def self.value_commitment(group, gens, value, blinding)
        Commitment.new(group, gens.g * value + gens.h * blinding)
      end

      # h_bases[i] = y^i H_i.  These are the inner-product argument bases and
      # also the bases used to build A and S.
      def self.scaled_h(gens, y_vec, mod)
        gens.h_vector.zip(y_vec).map { |point, yi| point * yi }
      end

      def self.transcript_after_v(group, n, v_point)
        domain = PROTOCOL_DOMAIN + ":group=#{group.name}:n=#{n}"
        transcript = Transcript.new(domain)
        transcript.append_integer('n', n)
        transcript.append_point('V', v_point)
        transcript
      end

      def self.transcript_with(group, n, v_point, a_point, s_point)
        transcript = transcript_after_v(group, n, v_point)
        transcript.append_point('A', a_point)
        transcript.append_point('S', s_point)
        transcript
      end

      def self.powers(scalar, count, mod)
        result = Array.new(count)
        power = 1
        count.times do |i|
          result[i] = power
          power = mod.call(power * scalar)
        end
        result
      end

      def self.geometric_sum(scalar, count, mod)
        sum = 0
        power = 1
        count.times do
          sum = mod.call(sum + power)
          power = mod.call(power * scalar)
        end
        sum
      end

      def self.inner(left, right, mod)
        sum = 0
        left.each_with_index { |li, i| sum += li * right[i] }
        mod.call(sum)
      end

      def self.delta(yn_sum, z, z2, z3, n, mod)
        mod.call((z - z2) * yn_sum - z3 * ((1 << n) - 1))
      end

      def self.verify!(group, n, commitment, proof, gens)
        field = Util.scalar_field(group)
        mod = ->(integer) { field.mod(integer) }
        rounds = n.bit_length - 1
        if proof.l_points.length != rounds || proof.r_points.length != rounds
          raise InvalidProofError, 'Inner-product argument has the wrong number of rounds.'
        end

        v_point = commitment.point
        transcript = transcript_after_v(group, n, v_point)
        y = transcript.challenge(group, 'y')
        y_vec = powers(y, n, mod)
        h_bases = scaled_h(gens, y_vec, mod)
        transcript.append_point('A', proof.a)
        transcript.append_point('S', proof.s)
        z = transcript.challenge(group, 'z')

        transcript.append_point('T1', proof.t1)
        transcript.append_point('T2', proof.t2)
        x = transcript.challenge(group, 'x')
        transcript.append_scalar(group, 't_hat', proof.t_hat)
        transcript.append_scalar(group, 'tau_x', proof.tau_x)
        transcript.append_scalar(group, 'mu', proof.mu)

        yn_sum = geometric_sum(y, n, mod)
        z2 = mod.call(z * z)
        z3 = mod.call(z2 * z)
        x2 = mod.call(x * x)
        d = delta(yn_sum, z, z2, z3, n, mod)

        lhs = gens.g * proof.t_hat + gens.h * proof.tau_x
        rhs = proof.t1 * x + proof.t2 * x2 + v_point * z2 + gens.g * d
        if lhs != rhs
          raise InvalidProofError, 'Polynomial t(x) commitment check failed.'
        end

        # Statement over G and the y-scaled H bases shared with A and S:
        #   P = A + x S - z<1,G> - <y z + z^2 2^n, H_scaled>
        #       + t_hat Q - mu H.
        g_terms = Array.new(n) { mod.call(-z) }
        h_terms = Array.new(n) { |i| mod.call(-y_vec[i] * z - z2 * (1 << i)) }
        p_point = proof.a + proof.s * x +
                  Util.multiscalar(group,
                    g_terms + h_terms + [proof.t_hat, mod.call(-proof.mu)],
                    gens.g_vector + h_bases + [gens.q, gens.h])

        InnerProductArgument.verify!(
          group: group, transcript: transcript, generators: gens,
          g_vector: gens.g_vector, h_vector: h_bases,
          c: proof.t_hat, p_point: p_point, proof: proof
        )
      end
    end
  end
end
