require_relative 'bulletproof/error'
require_relative 'bulletproof/util'
require_relative 'bulletproof/transcript'
require_relative 'bulletproof/generators'
require_relative 'bulletproof/range_proof_format'
require_relative 'bulletproof/commitment'
require_relative 'bulletproof/inner_product_argument'
require_relative 'bulletproof/range_proof'

module ECDSA
  # Pedersen commitments and Bulletproof range proofs for a single
  # committed value.  See {RangeProof} and {Commitment} for details.
  #
  # Currently supported range bit lengths are 8, 16, and 32, on any of
  # the gem's prime-order groups (secp256k1 by default).
  module Bulletproof
    # Default curve used by the convenience APIs.
    def self.default_group
      Group::Secp256k1
    end

    # Samples a uniformly random Pedersen blinding scalar in +[1, order)+
    # using +random+ (default: {SecureRandom}).
    def self.random_blinding(group = default_group, random: SecureRandom)
      Util.random_scalar(group, random)
    end

    # Creates a Pedersen commitment +V = value*G + blinding*H+.
    # @see RangeProof.commitment
    def self.commit(value, blinding, bit_length:, group: default_group, generators: nil)
      RangeProof.commitment(group: group, value: value, blinding: blinding,
                            bit_length: bit_length, generators: generators)
    end

    # Produces a range proof that the committed value lies in +[0, 2^n)+.
    # @see RangeProof.prove
    def self.prove(value, blinding, bit_length:, group: default_group, random: nil, generators: nil)
      RangeProof.prove(group: group, bit_length: bit_length, value: value,
                       blinding: blinding, random: random, generators: generators)
    end

    # Returns true iff +proof+ verifies for +commitment+ over the given
    # +bit_length+ range.
    # @see RangeProof.valid?
    def self.valid?(commitment, proof, bit_length:, group: default_group, generators: nil)
      RangeProof.valid?(commitment, proof,
                        bit_length: bit_length, group: group, generators: generators)
    end

    # Like {valid?} but raises on failure.
    # @see RangeProof.check_range_proof!
    def self.verify(commitment, proof, bit_length:, group: default_group, generators: nil)
      RangeProof.check_range_proof!(group, bit_length, commitment, proof, generators)
    end
  end
end
