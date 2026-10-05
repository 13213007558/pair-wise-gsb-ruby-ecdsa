module ECDSA
  module Bulletproof
    # Base class for errors raised by the Bulletproof range proof code.
    class Error < StandardError; end

    # Raised when an argument to the commitment/proof API is invalid
    # (unsupported bit length, out-of-range value, etc.).
    class ArgumentError < Error; end

    # Raised by {Bulletproof.check_range_proof!} when a proof fails any
    # verification step, including malformed encoding, a bad transcript
    # challenge, a failed Pedersen relation, or a failed inner-product check.
    class InvalidProofError < Error; end
  end
end
