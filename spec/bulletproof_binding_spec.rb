require 'spec_helper'

describe 'Bulletproof transcript and commitment binding' do
  let(:commitment) { File.binread(fixture_path('commitment')) }
  let(:proof_binary) { File.binread(fixture_path('proof')) }

  def fixture_path(name)
    File.expand_path("../fixtures/bulletproof_8_max_#{name}.bin", __FILE__)
  end

  it 'verifies the fixture and rejects a different commitment' do
    other_commitment, _randomness = ECDSA::Bulletproof.commit(1, rng: Random.new(10))

    expect(ECDSA::Bulletproof.valid_proof?(commitment, proof_binary)).to eq(true)
    expect(ECDSA::Bulletproof.valid_proof?(other_commitment, proof_binary)).to eq(false)
  end
end
