package chia

import (
	"encoding/hex"
	"github.com/blocktree/go-owcdrivers/addressEncoder"
	"github.com/blocktree/openwallet/v2/openwallet"
	"strings"
)

var (
	Default = AddressDecoderV2{}
)

var XCH_TestAddress = addressEncoder.AddressType{"bech32m", addressEncoder.XCHBech32Alphabet, "txch", "", 32, nil, nil}


//AddressDecoderV2
type AddressDecoderV2 struct {
	*openwallet.AddressDecoderV2Base
	wm *WalletManager
}

//NewAddressDecoder 地址解析器
func NewAddressDecoderV2( wm *WalletManager) *AddressDecoderV2 {
	decoder := AddressDecoderV2{}
	decoder.wm = wm
	return &decoder
}

//AddressDecode 地址解析
func (dec *AddressDecoderV2) AddressDecode(addr string, opts ...interface{}) ([]byte, error) {

	//puzzleHash := EncodePuzzleHash(addr,dec.wm.Config.Prefix)
	return []byte(addr), nil

}

//AddressEncode 地址编码
func (dec *AddressDecoderV2) AddressEncode(hash []byte, opts ...interface{}) (string, error) {

	hashStr :=  hex.EncodeToString(hash)
	puzzleHash,err := dec.wm.WalletClientIn.GetPuzzleHashByPubKey(hashStr)
	if err != nil{
		return "",err
	}

	return DecodePuzzleHash(puzzleHash,dec.wm.Config.Prefix),nil

}

// AddressVerify 地址校验
func (dec *AddressDecoderV2) AddressVerify(address string, opts ...interface{}) bool {
	if !strings.HasPrefix(address,dec.wm.Config.Prefix){
		return false
	}
	_,err := EncodePuzzleHashErr(address,dec.wm.Config.Prefix)
	if err != nil{
		return false
	}
	return true
}
