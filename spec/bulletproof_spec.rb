require 'spec_helper'

describe ECDSA::Bulletproof do
  it 'derives distinct secp256k1 generators without a caller-selectable base' do
    generators = described_class::Generators.for_bit_length(ECDSA::Group::Secp256k1, 8)
    points = [
      generators.value,
      generators.blinding,
      generators.vector_blinding
    ] + generators.g_vector + generators.h_vector

    expect(points.size).to eq(points.uniq.size)
    expect(points).to all(be_a(ECDSA::Point))
    expect(points.map(&:group).uniq).to eq [ECDSA::Group::Secp256k1]
  end

  it 'commits to a value with randomness' do
    point, generated_randomness = described_class.commit(123, rng: Random.new(99))
    expected = described_class::Generators.base.value_point.multiply_by_scalar(123) +
               described_class::Generators.base.blinding_point.multiply_by_scalar(generated_randomness)

    expect(point).to eq(expected)
    expect(generated_randomness).to be > 0
    expect(generated_randomness).to be < ECDSA::Group::Secp256k1.order
  end

  it 'rejects a value outside the range at proof generation' do
    _commitment_point, commitment_randomness = described_class.commit(256, rng: Random.new(7))
    expect do
      described_class.prove(256, commitment_randomness, 8, rng: Random.new(8))
    end.to raise_error ArgumentError, /Value must be in/
  end

  it 'rejects unsupported range widths' do
    _commitment, randomness = described_class.commit(0, rng: Random.new(999))
    expect do
      described_class.prove(0, randomness, 7, rng: Random.new(9))
    end.to raise_error ArgumentError, 'Supported range bit lengths are 8, 16, and 32.'
  end

end
