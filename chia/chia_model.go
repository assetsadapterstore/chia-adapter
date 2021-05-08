package chia

import (
	"encoding/json"
	"github.com/blocktree/openwallet/v2/openwallet"
	"math/big"
)

type Block struct {
	Height                   uint64  `json:"height" storm:"id"`
	BlockHash                string  `json:"header_hash"`
	PreviousHash             string  `json:"prev_hash"`
	RewardClaimsIncorporated []*Coin `json:"reward_claims_incorporated"`
}

type Coin struct {
	Amount         json.Number `json:"amount"`
	ParentCoinInfo string      `json:"parent_coin_info"`
	PuzzleHash     string      `json:"puzzle_hash"`
	CoinID         string      `json:"-"`
}

type CoinReq struct {
	Coin *Coin `json:"coin"`
}

type CoinRecord struct {
	CoinBase            bool                             `json:"coinbase"`
	ConfirmedBlockIndex uint64                           `json:"confirmed_block_index"`
	Spent               bool                             `json:"spent"`
	SpentBlockIndex     uint64                           `json:"spent_block_index"`
	Timestamp           uint64                           `json:"timestamp"`
	Coin                *Coin                            `json:"coin"`
	FilterFunc          openwallet.BlockScanTargetFuncV2 `json:"-"`
	Type                int8                             `json:"-"` // 1 is output ，2 is input
	BlockHash           string                           `json:"-"` // 1 is output ，2 is input
}

type Unspent struct {
	CoinRecords []*CoinRecord `json:"coin_records"`
}

type AddrBalance struct {
	Address string
	Balance *big.Int
}

func (c *Coin) GetAddress(prefix string) string {
	return DecodePuzzleHash(c.PuzzleHash, prefix)
}

type RawTrans struct {
	Bundle  *Bundle  `json:"bundle"`
	Msg     []string `json:"msg"`
	TxID    string   `json:"tx_id"`
	Address []string `json:"address"`
}

type Bundle struct {
	Signature     string           `json:"aggregated_signature"`
	CoinSolutions []*CoinSolutions `json:"coin_solutions"`
}

type SendTrans struct {
	Bundle *Bundle `json:"spend_bundle"`
}

type CoinSolutions struct {
	PuzzleReveal string `json:"puzzle_reveal"`
	Solution     string `json:"solution"`
	Coin         *Coin  `json:"coin"`
}

type BlockTrans struct {
	Additions []*CoinRecord `json:"additions"`
	Removals  []*CoinRecord `json:"removals"`
	BlockHash string        `json:"-"`
}

type Mempool struct {
	Additions []*Coin `json:"additions"`
	Removals  []*Coin `json:"removals"`
}

func (b *BlockTrans) GetCoinRecord() []*CoinRecord {
	records := make([]*CoinRecord, 0)
	removals := make(map[string]*CoinRecord)
	if len(b.Removals) > 0 {
		for _, r := range b.Removals {
			if r.Coin == nil {
				continue
			}
			r.Type = 2
			r.BlockHash = b.BlockHash
			removals[r.Coin.PuzzleHash] = r
			records = append(records, r)
		}
	}

	if len(b.Additions) > 0 {
		for _, a := range b.Additions {
			if a.Coin == nil {
				continue
			}
			//排除找零交易
			if _, ok := removals[a.Coin.PuzzleHash]; ok {
				continue
			}
			a.Type = 1
			a.BlockHash = b.BlockHash
			records = append(records, a)
		}
	}

	return records
}
