require 'spec_helper'

describe 'Bulletproof commitment-point fields' do
  it 'rejects tampering with each commitment point' do
    commitment = File.binread(fixture_path('commitment'))
    proof_binary = File.binread(fixture_path('proof'))

    [5, 38, 71, 104].each do |offset|
      altered = proof_binary.dup
      altered.setbyte(offset, altered.getbyte(offset) ^ 1)
      expect(ECDSA::Bulletproof.valid_proof?(commitment, altered)).to eq(false)
    end
  end

  def fixture_path(name)
    File.expand_path("../fixtures/bulletproof_8_max_#{name}.bin", __FILE__)
  end
end
