module ECDSA
  module Bulletproof
    # The log-sized inner-product argument embedded in a {RangeProof}.
    #
    # Proves knowledge of vectors +l+, +r+ with inner product +c+ for
    # fixed basis vectors +G'+/+H'+ and base +Q+, satisfying
    # +P = c Q - <l,G'> - <r,H'>+.
    #
    # Each logarithmic round publishes, for the split into low/high halves:
    #
    #   t_Lk = <l_hi, r_lo>,   t_Rk = <l_lo, r_hi>,
    #   L_k  = t_Lk Q - <l_hi, G_lo> - <r_lo, H_hi>,
    #   R_k  = t_Rk Q - <l_lo, G_hi> - <r_hi, H_lo>.
    #
    # A challenge +u_k+ is derived from the transcript.  Both sides fold
    # the vectors, bases, the statement point, and the public inner-product
    # scalar using reciprocal factors:
    #
    #   l' = u l_lo + u^-1 l_hi,   r' = u^-1 r_lo + u r_hi,
    #   G' = u^-1 G_lo + u G_hi,   H' = u H_lo + u^-1 H_hi,
    #   c' = u^-2 t_Lk + u^2 t_Rk + c,
    #   P' = P + u^-2 L_k + u^2 R_k.
    #
    # The explicit t_L/t_R scalars let the verifier fold +c+ exactly; they
    # are committed in the transcript before each challenge and reveal no
    # information about the witness beyond the already-public product.
    # After log(n) rounds the verifier checks
    #
    #   c_final Q == P_final + a' G'' + s' H''.
    module InnerProductArgument
      module_function

      # Runs the logarithmic folding protocol.
      def prove(group:, transcript:, generators:, g_vector:, h_vector:,
                l_vector:, r_vector:)
        field = Util.scalar_field(group)
        mod = ->(integer) { field.mod(integer) }
        q_point = generators.q

        g_vec = g_vector.dup
        h_vec = h_vector.dup
        l_vec = l_vector.map(&mod)
        r_vec = r_vector.map(&mod)

        l_points = []
        r_points = []
        t_l = []
        t_r = []

        while g_vec.length > 1
          half = g_vec.length / 2
          g_lo = g_vec[0, half]
          g_hi = g_vec[half, half]
          h_lo = h_vec[0, half]
          h_hi = h_vec[half, half]
          l_lo = l_vec[0, half]
          l_hi = l_vec[half, half]
          r_lo = r_vec[0, half]
          r_hi = r_vec[half, half]

          tl = dot(l_hi, r_lo, mod)
          tr = dot(l_lo, r_hi, mod)
          t_l << tl
          t_r << tr

          l_point = q_point * tl +
                    Util.multiscalar(group, l_hi.map { |s| mod.call(-s) } + r_lo.map { |s| mod.call(-s) },
                                     g_lo + h_hi)
          r_point = q_point * tr +
                    Util.multiscalar(group, l_lo.map { |s| mod.call(-s) } + r_hi.map { |s| mod.call(-s) },
                                     g_hi + h_lo)

          l_points << l_point
          r_points << r_point
          transcript.append_scalar(group, 'tL', tl)
          transcript.append_scalar(group, 'tR', tr)
          transcript.append_point('L', l_point)
          transcript.append_point('R', r_point)
          u = transcript.challenge(group, 'u')
          u_inv = Util.scalar_inverse(group, u)

          l_vec = fold_scalars(l_lo, l_hi, u, u_inv, mod)
          r_vec = fold_scalars(r_lo, r_hi, u_inv, u, mod)
          g_vec = fold_points(g_lo, g_hi, u_inv, u)
          h_vec = fold_points(h_lo, h_hi, u, u_inv)
        end

        {
          a_prime: l_vec.fetch(0),
          s_prime: r_vec.fetch(0),
          l_points: l_points,
          r_points: r_points,
          t_l: t_l,
          t_r: t_r,
        }
      end

      # Verifies the argument by folding the bases, the statement point,
      # and the public inner-product scalar with the transcript challenges.
      def verify!(group:, transcript:, generators:, g_vector:, h_vector:,
                  c:, p_point:, proof:)
        field = Util.scalar_field(group)
        mod = ->(integer) { field.mod(integer) }
        n = g_vector.length
        rounds = n.bit_length - 1

        g_vec = g_vector.dup
        h_vec = h_vector.dup
        statement = p_point
        c_scalar = c

        rounds.times do |i|
          tl = proof.t_l.fetch(i)
          tr = proof.t_r.fetch(i)
          transcript.append_scalar(group, 'tL', tl)
          transcript.append_scalar(group, 'tR', tr)
          transcript.append_point('L', proof.l_points.fetch(i))
          transcript.append_point('R', proof.r_points.fetch(i))
          u = transcript.challenge(group, 'u')
          u_inv = Util.scalar_inverse(group, u)
          u2 = mod.call(u * u)
          ui2 = mod.call(u_inv * u_inv)

          c_scalar = mod.call(c_scalar + ui2 * tl + u2 * tr)

          half = g_vec.length / 2
          g_lo = g_vec[0, half]
          g_hi = g_vec[half, half]
          h_lo = h_vec[0, half]
          h_hi = h_vec[half, half]
          g_vec = fold_points(g_lo, g_hi, u_inv, u)
          h_vec = fold_points(h_lo, h_hi, u, u_inv)

          statement = statement +
                      proof.l_points.fetch(i) * ui2 +
                      proof.r_points.fetch(i) * u2
        end

        a_prime = proof.a_prime
        s_prime = proof.s_prime
        if a_prime.zero? || s_prime.zero?
          raise InvalidProofError, 'Final inner-product scalars must be non-zero.'
        end

        lhs = generators.q * c_scalar
        rhs = statement + g_vec.fetch(0) * a_prime + h_vec.fetch(0) * s_prime
        if ENV['BP_DEBUG']
          $stderr.puts "DBGIPA cscalar==as=#{c_scalar == mod.call(a_prime * s_prime)}"
          $stderr.puts "DBGIPA lhs==rhs=#{lhs == rhs}"
        end
        raise InvalidProofError, 'Inner-product verification failed.' if lhs != rhs
        true
      end

      def dot(left, right, mod)
        sum = 0
        left.each_with_index { |li, i| sum += li * right[i] }
        mod.call(sum)
      end

      def fold_scalars(lo, high, c_lo, c_hi, mod)
        lo.each_with_index.map { |item, i| mod.call(item * c_lo + high[i] * c_hi) }
      end

      def fold_points(lo, high, c_lo, c_hi)
        lo.each_with_index.map { |point, i| point * c_lo + high[i] * c_hi }
      end
    end
  end
end
