require 'spec_helper'

describe ECDSA::SchnorrAdaptor do
  let(:group) { ECDSA::Group::Secp256k1 }
  let(:adaptor) { ECDSA::SchnorrAdaptor }

  # Deterministic test vector parameters.
  let(:secret_key) { 0x1111111111111111111111111111111111111111111111111111111111111111 }
  let(:adaptor_secret) { 0x2222222222222222222222222222222222222222222222222222222222222222 }
  let(:nonce) { 0x3333333333333333333333333333333333333333333333333333333333333333 }
  let(:message) { 'test vector message' }
  let(:public_key) { group.new_point(secret_key) }
  let(:adaptor_point) { group.new_point(adaptor_secret) }

  describe 'deterministic test vector' do
    # Expected values for secret_key = 0x11..11, adaptor_secret = 0x22..22,
    # nonce = 0x33..33, message = 'test vector message'.
    let(:expected_r_prime_x) { 0x3c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1 }
    let(:expected_r_prime_y) { 0x3b306b0fe085665d8fc1b28ae1676cd3ad6e08eaeda225fe38d0da4de55703e0 }
    let(:expected_pre_s) { 0x779cc0d7ef9eb6af1c84c2a6fb1420f7cb23f6f262f3b4b2147362f460fd6820 }
    let(:expected_r) { 0x9ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b }
    let(:expected_s) { 0x99bee2fa11c0d8d13ea6e4c91d364319ed4619148515d6d436958516831f8a42 }

    it 'reproduces the expected pre-signature' do
      pre = adaptor.presign(secret_key, adaptor_point, message, nonce: nonce)
      expect(pre.nonce_point.x).to eq expected_r_prime_x
      expect(pre.nonce_point.y).to eq expected_r_prime_y
      expect(pre.s).to eq expected_pre_s
    end

    it 'closes the full adaptor loop' do
      pre = adaptor.presign(secret_key, adaptor_point, message, nonce: nonce)
      expect(adaptor.verify_presignature(public_key, adaptor_point, message, pre)).to eq true

      signature = adaptor.adapt(pre, adaptor_secret, adaptor_point)
      expect(signature.r).to eq expected_r
      expect(signature.s).to eq expected_s
      expect(adaptor.verify(public_key, message, signature)).to eq true

      expect(adaptor.extract(pre, signature, adaptor_point)).to eq adaptor_secret
    end
  end

  describe 'closed loop with the default secure random nonce' do
    it 'works repeatedly' do
      3.times do
        pre = adaptor.presign(secret_key, adaptor_point, message)
        expect(adaptor.verify_presignature(public_key, adaptor_point, message, pre)).to eq true
        signature = adaptor.adapt(pre, adaptor_secret, adaptor_point)
        expect(adaptor.verify(public_key, message, signature)).to eq true
        expect(adaptor.extract(pre, signature, adaptor_point)).to eq adaptor_secret
      end
    end
  end

  describe 'parity conventions' do
    it 'handles a secret key whose public key has odd y (x-only convention)' do
      odd_secret = (1..20).find { |i| group.new_point(i).y.odd? }
      odd_public = group.new_point(odd_secret)
      pre = adaptor.presign(odd_secret, adaptor_point, message)
      expect(adaptor.verify_presignature(odd_public, adaptor_point, message, pre)).to eq true
      signature = adaptor.adapt(pre, adaptor_secret, adaptor_point)
      expect(adaptor.verify(odd_public, message, signature)).to eq true
      expect(adaptor.extract(pre, signature, adaptor_point)).to eq adaptor_secret
    end

    it 'ignores the y parity of the public key given to verify' do
      pre = adaptor.presign(secret_key, adaptor_point, message, nonce: nonce)
      signature = adaptor.adapt(pre, adaptor_secret, adaptor_point)
      flipped = group.new_point([public_key.x, group.field.mod(-public_key.y)])
      expect(adaptor.verify(flipped, message, signature)).to eq true
      expect(adaptor.verify_presignature(flipped, adaptor_point, message, pre)).to eq true
    end

    it 'retries the nonce until R = R\' + T has even y' do
      # With this adaptor point, nonce 2 gives an odd-y combined point.
      combined = group.new_point(2) + adaptor_point
      expect(combined.y).to be_odd
      pre = adaptor.presign(secret_key, adaptor_point, message, nonce: 2)
      expect(pre.nonce_point).not_to eq group.new_point(2)
      expect((pre.nonce_point + adaptor_point).y).to be_even
      expect(adaptor.verify_presignature(public_key, adaptor_point, message, pre)).to eq true
    end

    it 'always produces a combined nonce point with even y' do
      5.times do
        pre = adaptor.presign(secret_key, adaptor_point, message)
        expect((pre.nonce_point + adaptor_point).y).to be_even
      end
    end
  end

  describe 'verify_presignature' do
    let(:pre) { adaptor.presign(secret_key, adaptor_point, message, nonce: nonce) }

    it 'rejects a wrong message' do
      expect(adaptor.verify_presignature(public_key, adaptor_point, 'wrong', pre)).to eq false
    end

    it 'rejects a wrong public key' do
      other = group.new_point(0x4444)
      expect(adaptor.verify_presignature(other, adaptor_point, message, pre)).to eq false
    end

    it 'rejects a wrong adaptor point' do
      other = group.new_point(0x5555)
      expect(adaptor.verify_presignature(public_key, other, message, pre)).to eq false
    end

    it 'rejects a tampered s value' do
      tampered = ECDSA::SchnorrAdaptor::PreSignature.new(pre.nonce_point, (pre.s + 1) % group.order)
      expect(adaptor.verify_presignature(public_key, adaptor_point, message, tampered)).to eq false
    end

    it 'rejects a tampered nonce point' do
      tampered = ECDSA::SchnorrAdaptor::PreSignature.new(group.new_point(9), pre.s)
      expect(adaptor.verify_presignature(public_key, adaptor_point, message, tampered)).to eq false
    end

    it 'rejects malformed input without raising' do
      expect(adaptor.verify_presignature(public_key, adaptor_point, message, 'junk')).to eq false
      expect(adaptor.verify_presignature(public_key, adaptor_point, message,
                                         ECDSA::SchnorrAdaptor::PreSignature.new(nil, 1))).to eq false
    end
  end

  describe 'adapt' do
    let(:pre) { adaptor.presign(secret_key, adaptor_point, message, nonce: nonce) }

    it 'raises AdaptationError for a wrong adaptor secret' do
      expect do
        adaptor.adapt(pre, adaptor_secret + 1, adaptor_point)
      end.to raise_error(ECDSA::SchnorrAdaptor::AdaptationError)
    end

    it 'raises ArgumentError for an out-of-range adaptor secret' do
      expect { adaptor.adapt(pre, 0, adaptor_point) }.to raise_error(ArgumentError)
      expect { adaptor.adapt(pre, group.order, adaptor_point) }.to raise_error(ArgumentError)
    end
  end

  describe 'extract' do
    let(:pre) { adaptor.presign(secret_key, adaptor_point, message, nonce: nonce) }
    let(:signature) { adaptor.adapt(pre, adaptor_secret, adaptor_point) }

    it 'raises ExtractionError when the message was wrong' do
      other_pre = adaptor.presign(secret_key, adaptor_point, 'other message', nonce: nonce)
      expect do
        adaptor.extract(other_pre, signature, adaptor_point)
      end.to raise_error(ECDSA::SchnorrAdaptor::ExtractionError)
    end

    it 'raises ExtractionError when the public key was wrong' do
      other_pre = adaptor.presign(0x6666, adaptor_point, message, nonce: nonce)
      expect do
        adaptor.extract(other_pre, signature, adaptor_point)
      end.to raise_error(ECDSA::SchnorrAdaptor::ExtractionError)
    end

    it 'raises ExtractionError when the adaptor point is wrong' do
      expect do
        adaptor.extract(pre, signature, group.new_point(0x7777))
      end.to raise_error(ECDSA::SchnorrAdaptor::ExtractionError)
    end

    it 'raises ExtractionError for an unrelated final signature' do
      unrelated = ECDSA::SchnorrAdaptor::Signature.new(signature.r, (signature.s + 1) % group.order)
      expect do
        adaptor.extract(pre, unrelated, adaptor_point)
      end.to raise_error(ECDSA::SchnorrAdaptor::ExtractionError)
    end
  end

  describe 'input validation' do
    it 'rejects invalid secret keys' do
      expect { adaptor.presign(0, adaptor_point, message) }.to raise_error(ArgumentError)
      expect { adaptor.presign(group.order, adaptor_point, message) }.to raise_error(ArgumentError)
    end

    it 'rejects the infinity point as adaptor point' do
      expect { adaptor.presign(secret_key, group.infinity, message) }.to raise_error(ArgumentError)
    end

    it 'rejects adaptor points from other curves' do
      foreign = ECDSA::Group::Secp256r1.new_point(5)
      expect { adaptor.presign(secret_key, foreign, message) }.to raise_error(ArgumentError)
    end

    it 'rejects non-string messages' do
      expect { adaptor.presign(secret_key, adaptor_point, 1234) }.to raise_error(ArgumentError)
    end

    it 'rejects invalid explicit nonces' do
      expect { adaptor.presign(secret_key, adaptor_point, message, nonce: 0) }.to raise_error(ArgumentError)
      expect do
        adaptor.presign(secret_key, adaptor_point, message, nonce: group.order)
      end.to raise_error(ArgumentError)
    end
  end

  describe 'BIP-340 compatibility' do
    # Official test vectors from BIP-340 (indices 0 and 1).
    vectors = [
      {
        public_key: 'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9',
        message: '00' * 32,
        signature: 'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215' \
                   '25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0',
      },
      {
        public_key: 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
        message: '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
        signature: '6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341' \
                   '8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A',
      },
    ]

    vectors.each_with_index do |vector, index|
      it "verifies official test vector #{index}" do
        x = vector[:public_key].to_i(16)
        y = group.solve_for_y(x).find(&:even?)
        public_key = group.new_point([x, y])
        signature = ECDSA::SchnorrAdaptor::Signature.new(
          vector[:signature][0, 64].to_i(16),
          vector[:signature][64, 64].to_i(16),
        )
        expect(adaptor.verify(public_key, [vector[:message]].pack('H*'), signature)).to eq true
      end
    end

    it 'rejects a BIP-340 signature with a tampered message' do
      vector = vectors.first
      x = vector[:public_key].to_i(16)
      public_key = group.new_point([x, group.solve_for_y(x).find(&:even?)])
      signature = ECDSA::SchnorrAdaptor::Signature.new(
        vector[:signature][0, 64].to_i(16),
        vector[:signature][64, 64].to_i(16),
      )
      expect(adaptor.verify(public_key, ['01' * 32].pack('H*'), signature)).to eq false
    end
  end
end
