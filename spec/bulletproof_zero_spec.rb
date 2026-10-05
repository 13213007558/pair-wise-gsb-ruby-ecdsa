require 'spec_helper'

describe 'Zero-value Bulletproof range proof' do
  it 'verifies an 8-bit proof for zero' do
    commitment, randomness = ECDSA::Bulletproof.commit(0, rng: Random.new(1111))
    proof = ECDSA::Bulletproof.prove(0, randomness, 8, rng: Random.new(2222))

    expect(ECDSA::Bulletproof.valid_proof?(commitment, proof.to_binary)).to eq(true)
  end
end
