require 'spec_helper'
require 'digest/sha2'

describe ECDSA::Schnorr do
  let(:group) { ECDSA::Group::Secp256k1 }
  let(:message) { Digest::SHA256.digest('Schnorr test message') }
  let(:secret_key) { 0x1DCE8D2EC6184CAF0A972C7F9A4B7E9A1B2C3D4E5F60718293A4B5C6D7E8F901 }
  let(:public_key) { ECDSA::Schnorr.normalize_secret_key(secret_key).last }

  describe '.tagged_hash' do
    it 'matches the BIP-340 tagged hash construction' do
      tag_hash = Digest::SHA256.digest('BIP0340/challenge')
      expected = Digest::SHA256.digest(tag_hash + tag_hash + 'data')
      expect(ECDSA::Schnorr.tagged_hash('BIP0340/challenge', 'data')).to eq expected
    end
  end

  describe '.normalize_secret_key' do
    it 'returns a public key with even y' do
      (1..10).each do |i|
        _, point = ECDSA::Schnorr.normalize_secret_key(i * 0x1234567)
        expect(point.y.even?).to eq true
      end
    end

    it 'negates the secret key when the public key would have odd y' do
      n = group.order
      odd_key = (1..100).map { |i| i * 0xDEAD }.find { |k| group.generator.multiply_by_scalar(k).y.odd? }
      adjusted, point = ECDSA::Schnorr.normalize_secret_key(odd_key)
      expect(adjusted).to eq n - odd_key
      expect(point).to eq group.generator.multiply_by_scalar(odd_key).negate
    end

    it 'rejects out-of-range secret keys' do
      expect { ECDSA::Schnorr.normalize_secret_key(0) }.to raise_error(ArgumentError)
      expect { ECDSA::Schnorr.normalize_secret_key(group.order) }.to raise_error(ArgumentError)
    end
  end

  describe '.sign and .valid_signature?' do
    it 'signs with a random nonce by default and verifies' do
      signature = ECDSA::Schnorr.sign(secret_key, message)
      expect(ECDSA::Schnorr.valid_signature?(public_key, message, signature)).to eq true
    end

    it 'produces a deterministic signature with an explicit nonce' do
      sig1 = ECDSA::Schnorr.sign(secret_key, message, nonce: 0x1234)
      sig2 = ECDSA::Schnorr.sign(secret_key, message, nonce: 0x1234)
      expect(sig1.components).to eq sig2.components
    end

    it 'rejects a signature for a different message' do
      signature = ECDSA::Schnorr.sign(secret_key, message)
      other = Digest::SHA256.digest('other message')
      expect(ECDSA::Schnorr.valid_signature?(public_key, other, signature)).to eq false
    end

    it 'rejects a signature for a different public key' do
      signature = ECDSA::Schnorr.sign(secret_key, message)
      other_key = ECDSA::Schnorr.normalize_secret_key(secret_key + 1).last
      expect(ECDSA::Schnorr.valid_signature?(other_key, message, signature)).to eq false
    end

    it 'requires a 32-byte message' do
      expect { ECDSA::Schnorr.sign(secret_key, 'short') }.to raise_error(ArgumentError)
      expect(ECDSA::Schnorr.valid_signature?(public_key, 'short', ECDSA::Signature.new(1, 1))).to eq false
    end
  end

  describe 'BIP-340 official test vectors' do
    # https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
    vectors = [
      {
        index: 0,
        public_key: 'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9',
        message: '0000000000000000000000000000000000000000000000000000000000000000',
        signature: 'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215' \
          '25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0',
      },
      {
        index: 1,
        public_key: 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
        message: '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
        signature: '6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341' \
          '8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A',
      },
      {
        index: 2,
        public_key: 'DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8',
        message: '7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C',
        signature: '5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B' \
          'AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7',
      },
    ]

    def point_from_x(hex)
      group = ECDSA::Group::Secp256k1
      x = hex.to_i(16)
      y = group.solve_for_y(x).find(&:even?)
      group.new_point([x, y])
    end

    vectors.each do |vector|
      it "verifies test vector #{vector[:index]}" do
        public_key = point_from_x(vector[:public_key])
        message = [vector[:message]].pack('H*')
        signature = ECDSA::Signature.new(
          vector[:signature][0, 64].to_i(16),
          vector[:signature][64, 64].to_i(16),
        )
        expect(ECDSA::Schnorr.valid_signature?(public_key, message, signature)).to eq true
      end
    end
  end
end
