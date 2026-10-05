require 'spec_helper'

describe 'Bulletproof proof header encoding' do
  let(:commitment) { File.binread(fixture_path('commitment')) }
  let(:proof_binary) { File.binread(fixture_path('proof')) }

  def fixture_path(name)
    File.expand_path("../fixtures/bulletproof_8_max_#{name}.bin", __FILE__)
  end

  it 'rejects version and bit-length tampering' do
    altered_version = proof_binary.dup
    altered_version.setbyte(0, altered_version.getbyte(0) ^ 1)
    altered_width = proof_binary.dup
    altered_width.setbyte(4, altered_width.getbyte(4) ^ 8)

    expect(ECDSA::Bulletproof.valid_proof?(commitment, altered_version)).to eq(false)
    expect(ECDSA::Bulletproof.valid_proof?(commitment, altered_width)).to eq(false)
  end

  it 'rejects malformed lengths' do
    expect(ECDSA::Bulletproof.valid_proof?(commitment, proof_binary.byteslice(0, 400))).to eq(false)
    expect(ECDSA::Bulletproof.valid_proof?(commitment, proof_binary + "\0")).to eq(false)
  end

  it 'rejects malformed commitment encodings' do
    expect(ECDSA::Bulletproof.valid_proof?('not-a-point', proof_binary)).to eq(false)
  end
end
