require 'spec_helper'

describe 'Bulletproof inner-product reduction fields, second half' do
  it 'rejects the last three reduction point pairs' do
    commitment = File.binread(fixture_path('commitment'))
    proof_binary = File.binread(fixture_path('proof'))

    [396, 429, 462].each do |offset|
      altered = proof_binary.dup
      altered.setbyte(offset, altered.getbyte(offset) ^ 1)
      expect(ECDSA::Bulletproof.valid_proof?(commitment, altered)).to eq(false)
    end
  end

  def fixture_path(name)
    File.expand_path("../fixtures/bulletproof_8_max_#{name}.bin", __FILE__)
  end
end
