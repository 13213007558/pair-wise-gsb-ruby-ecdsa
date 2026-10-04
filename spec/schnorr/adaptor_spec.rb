require 'spec_helper'
require 'digest/sha2'

describe ECDSA::Schnorr::Adaptor do
  let(:group) { ECDSA::Group::Secp256k1 }
  let(:message) { Digest::SHA256.digest('ECDSA gem adaptor signature test vector') }
  let(:secret_key) { 0x1DCE8D2EC6184CAF0A972C7F9A4B7E9A1B2C3D4E5F60718293A4B5C6D7E8F901 }
  let(:public_key) { ECDSA::Schnorr.normalize_secret_key(secret_key).last }
  let(:adaptor_secret) { 0x02C0FFEE254296B9451F2E3D4C5B6A79887766554433221100FFEEDDCCBBAA99 }
  let(:adaptor_point) { group.generator.multiply_by_scalar(adaptor_secret) }

  # Deterministic test vector where R' = R + T has odd y, exercising the
  # negation branch of adapt/extract.
  let(:odd_vector) do
    {
      nonce: 0x1111,
      r_x: 0x7592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af,
      r_y: 0x554ee877af74284d5ac0aef1ccfa8ab27a9222ae977a1b457d79d38616eaa410,
      pre_s: 0xf885ca962e20c106f8ab0221a712e4554168b058f3e1f6b09a9da15dcb71f1e9,
      sig_r: 0x3e35d7cf2e2e821b90a9a39166a9e97f2e6510205c8a36ee984acbfca919e5a1,
      sig_s: 0x4b9357bac9ca83fc235cfa10c91b12ff0cec6387733877a2434ce513808a4bf,
    }
  end

  # Deterministic test vector where R' = R + T has even y.
  let(:even_vector) do
    {
      nonce: 0x2222,
      r_x: 0xe5740e63bad28081ed7cf654dd6c19029ca03382fc05ab5f5dda81f2c55b845b,
      r_y: 0x8dc1cf3a30ac29acf910275efd2ed6eb6511cfbeefd753804f664ede1eb2ff80,
      pre_s: 0xdff4370ffbb0ded99230e15b3803a2c61ba50c70fcb5f787af978b8857c64531,
      sig_r: 0x67c4ec2ceb0908e5b6062694e2cc9aa9a007224768b626300f98a8d7a9fb377c,
      sig_s: 0xe2b536fe20f37592d7500f98845f0d3fa41c72c640e91998b0977a662481efca,
    }
  end

  shared_examples 'a deterministic adaptor vector' do
    it 'reproduces the pre-signature exactly' do
      presignature = ECDSA::Schnorr::Adaptor.presign(
        secret_key, message, adaptor_point, nonce: vector[:nonce],
      )
      expect(presignature.nonce_point.x).to eq vector[:r_x]
      expect(presignature.nonce_point.y).to eq vector[:r_y]
      expect(presignature.s).to eq vector[:pre_s]
    end

    it 'passes pre-signature verification' do
      presignature = ECDSA::Schnorr::Adaptor.presign(
        secret_key, message, adaptor_point, nonce: vector[:nonce],
      )
      expect(
        ECDSA::Schnorr::Adaptor.valid_presignature?(public_key, message, adaptor_point, presignature),
      ).to eq true
    end

    it 'adapts to the expected final signature, which verifies as BIP-340' do
      presignature = ECDSA::Schnorr::Adaptor.presign(
        secret_key, message, adaptor_point, nonce: vector[:nonce],
      )
      signature = ECDSA::Schnorr::Adaptor.adapt(presignature, adaptor_secret)
      expect(signature.r).to eq vector[:sig_r]
      expect(signature.s).to eq vector[:sig_s]
      expect(ECDSA::Schnorr.valid_signature?(public_key, message, signature)).to eq true
    end

    it 'extracts the adaptor secret from the signature pair' do
      presignature = ECDSA::Schnorr::Adaptor.presign(
        secret_key, message, adaptor_point, nonce: vector[:nonce],
      )
      signature = ECDSA::Schnorr::Adaptor.adapt(presignature, adaptor_secret)
      extracted = ECDSA::Schnorr::Adaptor.extract_secret(presignature, signature, adaptor_point)
      expect(extracted).to eq adaptor_secret
    end
  end

  context 'when R + T has odd y' do
    let(:vector) { odd_vector }
    include_examples 'a deterministic adaptor vector'
  end

  context 'when R + T has even y' do
    let(:vector) { even_vector }
    include_examples 'a deterministic adaptor vector'
  end

  describe 'the full closed loop with a random nonce' do
    it 'presigns, verifies, adapts, and extracts' do
      presignature = ECDSA::Schnorr::Adaptor.presign(secret_key, message, adaptor_point)
      expect(
        ECDSA::Schnorr::Adaptor.valid_presignature?(public_key, message, adaptor_point, presignature),
      ).to eq true
      signature = ECDSA::Schnorr::Adaptor.adapt(presignature, adaptor_secret, adaptor_point: adaptor_point)
      expect(ECDSA::Schnorr.valid_signature?(public_key, message, signature)).to eq true
      expect(
        ECDSA::Schnorr::Adaptor.extract_secret(presignature, signature, adaptor_point),
      ).to eq adaptor_secret
    end
  end

  describe '.valid_presignature?' do
    let(:presignature) do
      ECDSA::Schnorr::Adaptor.presign(secret_key, message, adaptor_point, nonce: 0x9999)
    end

    it 'returns false for a different message' do
      other = Digest::SHA256.digest('wrong message')
      expect(
        ECDSA::Schnorr::Adaptor.valid_presignature?(public_key, other, adaptor_point, presignature),
      ).to eq false
    end

    it 'returns false for a different public key' do
      other_key = ECDSA::Schnorr.normalize_secret_key(secret_key + 1).last
      expect(
        ECDSA::Schnorr::Adaptor.valid_presignature?(other_key, message, adaptor_point, presignature),
      ).to eq false
    end

    it 'returns false for a different adaptor point' do
      other_point = group.generator.multiply_by_scalar(adaptor_secret + 1)
      expect(
        ECDSA::Schnorr::Adaptor.valid_presignature?(public_key, message, other_point, presignature),
      ).to eq false
    end

    it 'returns false when s is tampered with' do
      tampered = ECDSA::Schnorr::Adaptor::PreSignature.new(presignature.nonce_point, presignature.s + 1)
      expect(
        ECDSA::Schnorr::Adaptor.valid_presignature?(public_key, message, adaptor_point, tampered),
      ).to eq false
    end

    it 'returns false when s is out of range' do
      bad = ECDSA::Schnorr::Adaptor::PreSignature.new(presignature.nonce_point, 0)
      expect(
        ECDSA::Schnorr::Adaptor.valid_presignature?(public_key, message, adaptor_point, bad),
      ).to eq false
    end

    it 'returns false when the nonce point is not on the curve' do
      bad_point = ECDSA::Point.new(group, presignature.nonce_point.x, presignature.nonce_point.y + 1)
      bad = ECDSA::Schnorr::Adaptor::PreSignature.new(bad_point, presignature.s)
      expect(
        ECDSA::Schnorr::Adaptor.valid_presignature?(public_key, message, adaptor_point, bad),
      ).to eq false
    end

    it 'returns false when the adaptor point is not a valid public key' do
      expect(
        ECDSA::Schnorr::Adaptor.valid_presignature?(public_key, message, group.infinity, presignature),
      ).to eq false
    end
  end

  describe '.adapt' do
    let(:presignature) do
      ECDSA::Schnorr::Adaptor.presign(secret_key, message, adaptor_point, nonce: 0x8888)
    end

    it 'rejects an adaptor secret that does not match the given adaptor point' do
      expect {
        ECDSA::Schnorr::Adaptor.adapt(presignature, adaptor_secret + 1, adaptor_point: adaptor_point)
      }.to raise_error(ArgumentError, /does not match/)
    end

    it 'rejects out-of-range adaptor secrets' do
      expect { ECDSA::Schnorr::Adaptor.adapt(presignature, 0) }.to raise_error(ArgumentError)
      expect { ECDSA::Schnorr::Adaptor.adapt(presignature, group.order) }.to raise_error(ArgumentError)
    end

    it 'produces a signature that does not verify when the secret is wrong' do
      signature = ECDSA::Schnorr::Adaptor.adapt(presignature, adaptor_secret + 1)
      expect(ECDSA::Schnorr.valid_signature?(public_key, message, signature)).to eq false
    end
  end

  describe '.extract_secret' do
    let(:presignature) do
      ECDSA::Schnorr::Adaptor.presign(secret_key, message, adaptor_point, nonce: 0x7777)
    end
    let(:signature) { ECDSA::Schnorr::Adaptor.adapt(presignature, adaptor_secret) }

    it 'raises ExtractionError when the adaptor point is wrong' do
      other_point = group.generator.multiply_by_scalar(adaptor_secret + 1)
      expect {
        ECDSA::Schnorr::Adaptor.extract_secret(presignature, signature, other_point)
      }.to raise_error(ECDSA::Schnorr::Adaptor::ExtractionError)
    end

    it 'raises ExtractionError when the pre-signature is from a different message' do
      other = Digest::SHA256.digest('a different message')
      other_pre = ECDSA::Schnorr::Adaptor.presign(secret_key, other, adaptor_point, nonce: 0x7777)
      expect {
        ECDSA::Schnorr::Adaptor.extract_secret(other_pre, signature, adaptor_point)
      }.to raise_error(ECDSA::Schnorr::Adaptor::ExtractionError)
    end

    it 'raises ExtractionError when the final signature was made by a different key' do
      other_pre = ECDSA::Schnorr::Adaptor.presign(secret_key + 1, message, adaptor_point, nonce: 0x7777)
      other_sig = ECDSA::Schnorr::Adaptor.adapt(other_pre, adaptor_secret)
      expect {
        ECDSA::Schnorr::Adaptor.extract_secret(presignature, other_sig, adaptor_point)
      }.to raise_error(ECDSA::Schnorr::Adaptor::ExtractionError)
    end

    it 'raises ExtractionError when the signature is unrelated' do
      unrelated = ECDSA::Schnorr.sign(secret_key, message)
      expect {
        ECDSA::Schnorr::Adaptor.extract_secret(presignature, unrelated, adaptor_point)
      }.to raise_error(ECDSA::Schnorr::Adaptor::ExtractionError)
    end

    it 'raises ExtractionError when the adaptor point is not a valid public key' do
      expect {
        ECDSA::Schnorr::Adaptor.extract_secret(presignature, signature, group.infinity)
      }.to raise_error(ArgumentError)
    end
  end

  describe '.presign' do
    it 'rejects invalid adaptor points' do
      expect {
        ECDSA::Schnorr::Adaptor.presign(secret_key, message, group.infinity)
      }.to raise_error(ArgumentError)
    end

    it 'rejects out-of-range nonces' do
      expect {
        ECDSA::Schnorr::Adaptor.presign(secret_key, message, adaptor_point, nonce: 0)
      }.to raise_error(ArgumentError)
    end
  end
end
