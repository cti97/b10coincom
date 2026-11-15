package consensus

import (
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/types"
)

// Exported certificate primitives (M7). A checkpoint is (height, block, state
// snapshot, certificate), and the certificate is the record the chain archives
// for that height (audit C-7): this file is what lets a package OUTSIDE the
// syncer encode, decode and re-tally one without a second, drifting copy of the
// quorum rules.
//
// The rules themselves are NOT re-implemented here. VerifyCommitCertificate
// decodes the stored vote bytes and hands them to verifyCertificateVotes, the
// same body the syncer's certificate gate runs on a block it is about to
// adopt. A checkpoint that passes this check therefore carries exactly the
// evidence a live commit is made of.

// ErrBadCheckpoint reports a checkpoint whose certificate does not prove a
// quorum commitment of the block and state it carries. It deliberately wraps
// the certificate gate's own error, so a caller can ask either question.
var ErrBadCheckpoint = errors.New("consensus: checkpoint is not verifiable")

// EncodeCertificate renders the stored certificate form for (round, votes): the
// round, then a count-prefixed list of encoded votes. It is the format the
// chain's certificate log holds (encodeCertRecord), exported so a checkpoint
// can be written without reaching into the syncer.
func EncodeCertificate(round uint32, votes []*Vote) []byte {
	encoded := make([][]byte, 0, len(votes))
	for _, v := range votes {
		encoded = append(encoded, EncodeVote(v))
	}
	return encodeCertRecord(round, encoded)
}

// DecodeCertificate reads EncodeCertificate's output. It is strict - trailing
// bytes, a bad count and an undecodable vote are all errors - so a checkpoint's
// certificate cannot be a byte string with a second interpretation.
func DecodeCertificate(b []byte) (uint32, [][]byte, error) {
	return decodeCertRecord(b)
}

// VerifyCommitCertificate re-tallies a stored certificate against vals and
// reports whether it proves a quorum of that committee precommitted blk at
// (blk.Header.Height, round).
//
// The committee is the CALLER's, and that is the whole trust argument of a
// checkpoint: M7's caller passes the GENESIS committee, the chain's anchor, so
// a checkpoint is adopted only if the keys that founded the chain signed the
// block whose header commits the checkpoint's state root. It is NOT the
// block's epoch committee - that is what the syncer uses, because the syncer is
// judging a block of a live chain whose rotation history it already holds. The
// difference is stated in checkpoint.go's assumption note.
func VerifyCommitCertificate(vals []genesis.Validator, blk *types.Block, round uint32, encoded [][]byte) error {
	if blk == nil {
		return fmt.Errorf("%w: no block to verify the certificate against", ErrBadCheckpoint)
	}
	votes := make([]*Vote, 0, len(encoded))
	for i, raw := range encoded {
		v, err := DecodeVote(raw)
		if err != nil {
			return fmt.Errorf("%w: certificate vote %d does not decode: %v", ErrBadCheckpoint, i+1, err)
		}
		votes = append(votes, v)
	}
	if err := verifyCertificateVotes(vals, blk, round, votes); err != nil {
		return fmt.Errorf("%w: %w", ErrBadCheckpoint, err)
	}
	return nil
}
