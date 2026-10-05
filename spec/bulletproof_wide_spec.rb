require 'spec_helper'

describe 'Wide Bulletproof range proofs' do
  before do
    unless ENV['BULLETPROOF_WIDE_SPECS'] == '1'
    skip 'Set BULLETPROOF_WIDE_SPECS=1 to run 16- and 32-bit range proofs.'
    end
  end

  [16, 32].each do |bit_length|
    [0, (1 << bit_length) - 1].each do |value|
      it "verifies a #{bit_length}-bit proof for #{value}" do
        commitment, randomness = ECDSA::Bulletproof.commit(
          value,
          rng: Random.new(value + bit_length)
        )
        proof = ECDSA::Bulletproof.prove(
          value,
          randomness,
          bit_length,
          rng: Random.new(value + bit_length + 1000)
        )

        expect(ECDSA::Bulletproof.valid_proof?(commitment, proof.to_binary)).to eq(true)
      end
    end

    it "rejects 2^#{bit_length} during proof generation" do
      _commitment, randomness = ECDSA::Bulletproof.commit(
        1 << bit_length,
        rng: Random.new(bit_length + 99)
      )

      expect do
        ECDSA::Bulletproof.prove(
          1 << bit_length,
          randomness,
          bit_length,
          rng: Random.new(bit_length + 100)
        )
      end.to raise_error ArgumentError, /Value must be in/
    end
  end
end
