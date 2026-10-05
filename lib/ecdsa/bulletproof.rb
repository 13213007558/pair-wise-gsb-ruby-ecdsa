# encoding: ASCII-8BIT

require 'digest/sha2'
require_relative '../ecdsa'
require_relative 'bulletproof/generators'
require_relative 'bulletproof/transcript'
require_relative 'bulletproof/pedersen'
require_relative 'bulletproof/proof'
require_relative 'bulletproof/range_proof'

module ECDSA
  module Bulletproof
    DOMAIN = 'ECDSA Ruby Bulletproof range proof v1 secp256k1'
    SUPPORTED_BIT_LENGTHS = [8, 16, 32].freeze

    def self.commit(value, options = {})
      Pedersen.commit(value, options)
    end

    def self.prove(value, randomness, bit_length, options = {})
      RangeProof.prove(value, randomness, bit_length, options)
    end

    def self.valid_proof?(commitment, proof, options = {})
      RangeProof.valid?(commitment, proof, options)
    end

    def self.verify(commitment, proof, options = {})
      RangeProof.verify(commitment, proof, options)
    end
  end
end
