require 'spec_helper'

describe 'Maximum-value Bulletproof range proof' do
  it 'verifies an 8-bit proof for 255' do
    commitment, randomness = ECDSA::Bulletproof.commit(255, rng: Random.new(1234))
    proof = ECDSA::Bulletproof.prove(255, randomness, 8, rng: Random.new(4321))

    expect(ECDSA::Bulletproof.valid_proof?(commitment, proof.to_binary)).to eq(true)
  end
end
