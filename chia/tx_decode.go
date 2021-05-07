/*
* Copyright 2018 The openwallet Authors
* This file is part of the openwallet library.
*
* The openwallet library is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* The openwallet library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
 */
package chia

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/blocktree/go-owcrypt"
	"github.com/blocktree/openwallet/v2/common"
	"github.com/blocktree/openwallet/v2/openwallet"
	"github.com/shopspring/decimal"
	"math/big"
	"sort"
	"strings"
	"time"
)

type XchTransactionDecoder struct {
	openwallet.TransactionDecoderBase
	wm *WalletManager //钱包管理者
}

//NewTransactionDecoder 交易单解析器
func NewTransactionDecoder(wm *WalletManager) *XchTransactionDecoder {
	decoder := XchTransactionDecoder{}
	decoder.wm = wm
	return &decoder
}

func (decoder *XchTransactionDecoder) GetRawTransactionFeeRate() (feeRate string, unit string, err error) {

	return decoder.wm.Config.Fee, "XCH", nil
}

func (decoder *XchTransactionDecoder) CreateSimpleRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction, tmpNonce *uint64) error {

	var (
		accountID       = rawTx.Account.AccountID
		findAddrBalance *AddrBalance
	)

	//获取wallet
	addresses, err := wrapper.GetAddressList(0, -1,
		"AccountID", accountID)
	if err != nil {
		return openwallet.NewError(openwallet.ErrAddressNotFound, err.Error())
	}

	if len(addresses) == 0 {
		return openwallet.Errorf(openwallet.ErrAccountNotAddress, "[%s] have not addresses", accountID)
	}

	searchAddrs := make([]string, 0)
	for _, address := range addresses {
		searchAddrs = append(searchAddrs, address.Address)
	}

	addrBalanceArray, err := decoder.wm.Blockscanner.GetBalanceByAddress(searchAddrs...)
	if err != nil {
		return openwallet.NewError(openwallet.ErrCallFullNodeAPIFailed, err.Error())
	}

	var amountStr string
	for _, v := range rawTx.To {
		//to = k
		amountStr = v
		break
	}

	//amount := common.StringNumToBigIntWithExp(amountStr, decoder.wm.Decimal())

	//地址余额从大到小排序
	sort.Slice(addrBalanceArray, func(i int, j int) bool {
		a_amount, _ := decimal.NewFromString(addrBalanceArray[i].Balance)
		b_amount, _ := decimal.NewFromString(addrBalanceArray[j].Balance)
		if a_amount.LessThan(b_amount) {
			return false
		} else {
			return true
		}
	})

	for _, addrBalance := range addrBalanceArray {
		amount := common.StringNumToBigIntWithExp(amountStr, decoder.wm.Decimal())
		//检查余额是否超过最低转账
		addrBalance_BI := common.StringNumToBigIntWithExp(addrBalance.Balance, decoder.wm.Decimal())

		//总消耗数量 = 转账数量 + 手续费
		totalAmount := new(big.Int)
		totalAmount.Add(amount, big.NewInt(0))
		if addrBalance_BI.Cmp(totalAmount) < 0 {
			continue
		}

		//只要找到一个合适使用的地址余额就停止遍历
		findAddrBalance = &AddrBalance{Address: addrBalance.Address, Balance: addrBalance_BI}
		break
	}

	if findAddrBalance == nil {
		return openwallet.Errorf(openwallet.ErrInsufficientBalanceOfAccount, "the balance: %s is not enough", amountStr)
	}
	fee, _, _ := decoder.GetRawTransactionFeeRate()
	//最后创建交易单
	createTxErr := decoder.createRawTransaction(
		wrapper,
		rawTx,
		findAddrBalance,
		fee,
		"",
		tmpNonce)
	if createTxErr != nil {
		return createTxErr
	}

	return nil
}

//CreateRawTransaction 创建交易单
func (decoder *XchTransactionDecoder) CreateRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {
	if !rawTx.Coin.IsContract {
		return decoder.CreateSimpleRawTransaction(wrapper, rawTx, nil)
	} else {
		return openwallet.Errorf(openwallet.ErrSignRawTransactionFailed, "transaction not support erc20")
	}

}

//SignRawTransaction 签名交易单
func (decoder *XchTransactionDecoder) SignRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {

	if rawTx.Signatures == nil || len(rawTx.Signatures) == 0 {
		//decoder.wm.Log.Std.Error("len of signatures error. ")
		return openwallet.Errorf(openwallet.ErrSignRawTransactionFailed, "transaction signature is empty")
	}

	key, err := wrapper.HDKey()
	if err != nil {
		decoder.wm.Log.Error("get HDKey from wallet wrapper failed, err=%v", err)
		return err
	}

	if _, exist := rawTx.Signatures[rawTx.Account.AccountID]; !exist {
		decoder.wm.Log.Std.Error("wallet[%v] signature not found ", rawTx.Account.AccountID)
		return openwallet.Errorf(openwallet.ErrSignRawTransactionFailed, "wallet signature not found ")
	}

	if len(rawTx.Signatures[rawTx.Account.AccountID]) == 0 {
		decoder.wm.Log.Error("signature failed in account[%v].", rawTx.Account.AccountID)
		return openwallet.Errorf(openwallet.ErrSignRawTransactionFailed, "signature failed in account.")
	}

	signnodes := rawTx.Signatures[rawTx.Account.AccountID]
	if len(signnodes) == 0 {
		return openwallet.Errorf(openwallet.ErrSignRawTransactionFailed, "transaction signature is empty")
	}
	for _, signnode := range signnodes {
		fromAddr := signnode.Address

		childKey, _ := key.DerivedKeyWithPath(fromAddr.HDPath, owcrypt.ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)
		keyBytes, err := childKey.GetPrivateKeyBytes()
		if err != nil {
			return openwallet.NewError(openwallet.ErrSignRawTransactionFailed, err.Error())
		}
		message, err := hex.DecodeString(signnode.Message)
		if err != nil {
			return err
		}
		key2 := Calculate_synthetic_secret_key(keyBytes)
		signature, _, sigErr := owcrypt.Signature(key2, nil, message, decoder.wm.CurveType())
		if sigErr != owcrypt.SUCCESS {
			return fmt.Errorf("transaction hash sign failed")
		}
		signnode.Signature = hex.EncodeToString(signature)
	}

	return nil
}

// SubmitRawTransaction 广播交易单
func (decoder *XchTransactionDecoder) SubmitRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) (*openwallet.Transaction, error) {

	if len(rawTx.Signatures) != 1 {
		decoder.wm.Log.Std.Error("len of signatures error. ")
		return nil, openwallet.Errorf(openwallet.ErrSubmitRawTransactionFailed, "len of signatures error. ")
	}

	sigs, exist := rawTx.Signatures[rawTx.Account.AccountID]
	if !exist {
		decoder.wm.Log.Std.Error("wallet[%v] signature not found ", rawTx.Account.AccountID)
		return nil, openwallet.Errorf(openwallet.ErrSubmitRawTransactionFailed, "wallet signature not found ")
	}

	newSig := make([][]byte, 0)
	for _, sig := range sigs {
		sigByte, _ := hex.DecodeString(sig.Signature)
		newSig = append(newSig, sigByte)
	}

	finalSig, _ := owcrypt.AggregateSignatures(decoder.wm.CurveType(), newSig...)

	sig := "0x" + hex.EncodeToString(finalSig)

	rawHex, err := hex.DecodeString(rawTx.RawHex)
	if err != nil {
		decoder.wm.Log.Error("rawTx.RawHex decode failed, err:", err)
		return nil, err
	}

	rawTrans := &RawTrans{}
	err = json.Unmarshal(rawHex, rawTrans)
	if err != nil {
		return nil, errors.New("get_coin_records_by_puzzle_hash error2,json error")
	}

	bundle := rawTrans.Bundle
	bundle.Signature = sig
	sendTrans := &SendTrans{}
	sendTrans.Bundle = bundle
	toMap := rawTx.To
	targetTo := ""
	for address, _ := range toMap {
		targetTo = address
	}
	targetPuzzle := EncodePuzzleHash(targetTo, decoder.wm.Config.Prefix)

	//完成以上操作最终才进行提交
	_, err = decoder.wm.WalletClient.PutTx(sendTrans)
	if err != nil {
		return nil, err
	}

	memCoins, err := decoder.wm.WalletClient.GetMempoolByTxID(rawTrans.TxID)
	if err != nil {
		return nil, errors.New("submitRawTransaction error3,json error")
	}
	//把目标源的coinID填充进去
	for _, coin := range memCoins {
		if coin.PuzzleHash == targetPuzzle {
			newCoin, err := decoder.wm.WalletClientIn.GetCoinID(coin)
			if err != nil {
				return nil, errors.New(" Submit err,GetCoinID error, error:" + err.Error())
			}
			rawTx.TxID = newCoin.CoinID
			break
		}
	}

	rawTx.IsSubmit = true
	decimals := int32(decoder.wm.Decimal())
	fees := rawTx.Fees

	//记录一个交易单
	owtx := &openwallet.Transaction{
		From:       rawTx.TxFrom,
		To:         rawTx.TxTo,
		Amount:     rawTx.TxAmount,
		Coin:       rawTx.Coin,
		TxID:       rawTx.TxID,
		Decimal:    decimals,
		AccountID:  rawTx.Account.AccountID,
		Fees:       fees,
		SubmitTime: time.Now().Unix(),
		TxType:     0,
	}
	owtx.WxID = openwallet.GenTransactionWxID(owtx)

	blockScanner := decoder.wm.Blockscanner.(*BlockScanner)
	err = blockScanner.SaveTransaction(owtx)
	if err != nil {
		decoder.wm.Log.Error("SaveTransaction failed, err:", err)
	}
	return owtx, nil
}

//VerifyRawTransaction 验证交易单，验证交易单并返回加入签名后的交易单
func (decoder *XchTransactionDecoder) VerifyRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {

	if rawTx.Signatures == nil || len(rawTx.Signatures) == 0 {
		//decoder.wm.Log.Std.Error("len of signatures error. ")
		return openwallet.Errorf(openwallet.ErrVerifyRawTransactionFailed, "transaction signature is empty")
	}

	accountSigs, exist := rawTx.Signatures[rawTx.Account.AccountID]
	if !exist {
		decoder.wm.Log.Std.Error("wallet[%v] signature not found ", rawTx.Account.AccountID)
		return errors.New("wallet signature not found ")
	}

	if len(accountSigs) == 0 {
		//decoder.wm.Log.Std.Error("len of signatures error. ")
		return openwallet.Errorf(openwallet.ErrVerifyRawTransactionFailed, "transaction signature is empty")
	}

	for _, accountSig := range accountSigs {
		sig := accountSig.Signature
		msg := accountSig.Message
		pubkey := accountSig.Address.PublicKey
		sigByte, _ := hex.DecodeString(sig)
		pubByte, _ := hex.DecodeString(pubkey)
		msgByte, _ := hex.DecodeString(msg)
		ret := owcrypt.Verify(pubByte, nil, msgByte, sigByte, decoder.wm.CurveType())

		if ret != owcrypt.SUCCESS {
			//errinfo := fmt.Sprintf("verify error, ret:%v\n", "0x"+strconv.FormatUint(uint64(ret), 16))
			//fmt.Println(errinfo)
			//return errors.New(errinfo)
		}
	}

	return nil
}

//CreateSummaryRawTransaction 创建汇总交易，返回原始交易单数组
func (decoder *XchTransactionDecoder) CreateSummaryRawTransaction(wrapper openwallet.WalletDAI, sumRawTx *openwallet.SummaryRawTransaction) ([]*openwallet.RawTransaction, error) {
	var (
		rawTxWithErrArray []*openwallet.RawTransactionWithError
		rawTxArray        = make([]*openwallet.RawTransaction, 0)
		err               error
	)
	if sumRawTx.Coin.IsContract {

	} else {
		rawTxWithErrArray, err = decoder.CreateSimpleSummaryRawTransaction(wrapper, sumRawTx)
	}
	if err != nil {
		return nil, err
	}
	for _, rawTxWithErr := range rawTxWithErrArray {
		if rawTxWithErr.Error != nil {
			continue
		}
		rawTxArray = append(rawTxArray, rawTxWithErr.RawTx)
	}
	return rawTxArray, nil
}

//CreateSimpleSummaryRawTransaction 创建XCH汇总交易
func (decoder *XchTransactionDecoder) CreateSimpleSummaryRawTransaction(wrapper openwallet.WalletDAI, sumRawTx *openwallet.SummaryRawTransaction) ([]*openwallet.RawTransactionWithError, error) {

	var (
		rawTxArray      = make([]*openwallet.RawTransactionWithError, 0)
		accountID       = sumRawTx.Account.AccountID
		minTransfer     = common.StringNumToBigIntWithExp(sumRawTx.MinTransfer, decoder.wm.Decimal())
		retainedBalance = common.StringNumToBigIntWithExp(sumRawTx.RetainedBalance, decoder.wm.Decimal())
	)

	if minTransfer.Cmp(retainedBalance) < 0 {
		return nil, openwallet.Errorf(openwallet.ErrCreateRawTransactionFailed, "mini transfer amount must be greater than address retained balance")
	}

	//获取wallet
	addresses, err := wrapper.GetAddressList(sumRawTx.AddressStartIndex, sumRawTx.AddressLimit,
		"AccountID", sumRawTx.Account.AccountID)
	if err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, openwallet.Errorf(openwallet.ErrAccountNotAddress, "[%s] have not addresses", accountID)
	}

	searchAddrs := make([]string, 0)
	for _, address := range addresses {
		searchAddrs = append(searchAddrs, address.Address)
	}

	addrBalanceArray, err := decoder.wm.Blockscanner.GetBalanceByAddress(searchAddrs...)
	if err != nil {
		return nil, err
	}
	coinRecordList := make([]*CoinRecord, 0)
	coinRecordCount := int64(0)
	totalAmount := decimal.Zero
	from := make([]string, 0)
	for _, addrBalance := range addrBalanceArray {
		if coinRecordCount > decoder.wm.Config.MaxUnSpentCount {
			break
		}
		singleAmount := decimal.Zero
		//检查余额是否超过最低转账
		addrBalance_BI := common.StringNumToBigIntWithExp(addrBalance.Balance, decoder.wm.Decimal())
		if addrBalance_BI.Cmp(minTransfer) < 0 {
			continue
		}
		if addrBalance_BI.Uint64() == 0 {
			continue
		}

		puzzleHash := EncodePuzzleHash(addrBalance.Address, decoder.wm.Config.Prefix)
		unspent, err := decoder.wm.WalletClient.GetCoinRecordsByPuzzleHash(puzzleHash, false)
		if err != nil {
			continue
		}

		//获取未花
		if len(unspent.CoinRecords) > 0 {
			for _, us := range unspent.CoinRecords {
				if coinRecordCount > decoder.wm.Config.MaxUnSpentCount {
					break
				}
				thisAmount, _ := decimal.NewFromString(us.Coin.Amount.String())
				thisAmount = thisAmount.Shift(-decoder.wm.Decimal())
				singleAmount = singleAmount.Add(thisAmount)
				totalAmount = totalAmount.Add(thisAmount)
				coinRecordList = append(coinRecordList, us)
				coinRecordCount = coinRecordCount + 1
			}

		}
		thisFrom := fmt.Sprintf("%s:%s", addrBalance.Address, singleAmount.String())
		from = append(from, thisFrom)
		decoder.wm.Log.Debugf("address: %v", addrBalance.Address)
		if singleAmount.String() == "0" {
			decoder.wm.Log.Debugf("sumAmount: %v", singleAmount)
		}
		decoder.wm.Log.Debugf("sumAmount: %v", singleAmount)

	}
	fee := decoder.wm.Config.SummaryFee
	decoder.wm.Log.Debugf("totalAmount: %v", totalAmount)
	decoder.wm.Log.Debugf("fee: %v", fee)
	//创建一笔交易单
	rawTx := &openwallet.RawTransaction{
		Coin:    sumRawTx.Coin,
		Account: sumRawTx.Account,
		To: map[string]string{
			sumRawTx.SummaryAddress: totalAmount.String(),
		},
		Required: 1,
	}

	createTxErr := decoder.createRawTransactionSummary(
		wrapper,
		rawTx,
		coinRecordList,
		from,
		fee,
	)
	rawTxWithErr := &openwallet.RawTransactionWithError{
		RawTx: rawTx,
		Error: createTxErr,
	}

	//创建成功，添加到队列
	rawTxArray = append(rawTxArray, rawTxWithErr)

	return rawTxArray, nil
}

//createRawTransaction
func (decoder *XchTransactionDecoder) createRawTransactionSummary(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction, coinRecords []*CoinRecord, from []string, fee string) *openwallet.Error {

	var (
		accountTotalSent = decimal.Zero
		txTo             = make([]string, 0)
		keySignList      = make([]*openwallet.KeySignature, 0)
		amountStr        string
		destination      string
	)

	for k, v := range rawTx.To {
		destination = k
		amountStr = v
		break
	}

	amountDec, _ := decimal.NewFromString(amountStr)
	accountTotalSent = accountTotalSent.Add(amountDec)

	txTo = []string{fmt.Sprintf("%s:%s", destination, amountStr)}

	feesDec, _ := decimal.NewFromString(rawTx.Fees)
	accountTotalSent = accountTotalSent.Add(feesDec)
	totalFeeDecimal, _ := decimal.NewFromString(fee)
	rawTx.Fees = totalFeeDecimal.String()
	rawTx.TxAmount = accountTotalSent.String()
	rawTx.TxFrom = from
	rawTx.TxTo = txTo

	maxPrice, _ := decimal.NewFromString("18446744073709551615")
	if accountTotalSent.GreaterThanOrEqual(maxPrice) {
		return openwallet.NewError(openwallet.ErrAccountNotAddress, "over max 18446744073709551615")
	}

	//totalSentInt := uint64(accountTotalSent.Shift(decoder.wm.Decimal()).IntPart())
	feeInt := uint64(totalFeeDecimal.Shift(decoder.wm.Decimal()).IntPart())

	pubs := make([]string, 0)
	for _, c := range coinRecords {
		puzzleHash := c.Coin.PuzzleHash
		add := DecodePuzzleHash(puzzleHash, decoder.wm.Config.Prefix)
		addr, err := wrapper.GetAddress(add)
		if err != nil {
			return openwallet.NewError(openwallet.ErrUnknownException, "cant find address:"+add+",err:"+err.Error())
		}
		pubs = append(pubs, addr.PublicKey)
	}

	//生成汇总结构
	rawTrans, err := decoder.wm.WalletClientIn.CreateSummaryRawTransaction(pubs, coinRecords, destination, feeInt)
	if err != nil {
		return openwallet.NewError(openwallet.ErrUnknownException, err.Error())
	}

	//bundle := rawTrans.Bundle
	rawHex, _ := json.Marshal(rawTrans)
	if rawTx.Signatures == nil {
		rawTx.Signatures = make(map[string][]*openwallet.KeySignature)
	}

	if len(rawTrans.Msg) != len(coinRecords) {
		return openwallet.NewError(openwallet.ErrUnknownException, "msg count not equal the")
	}

	for key, msg := range rawTrans.Msg {
		coin := coinRecords[key]
		puzzleHash := coin.Coin.PuzzleHash
		add := DecodePuzzleHash(puzzleHash, decoder.wm.Config.Prefix)
		addr, err := wrapper.GetAddress(add)
		if err != nil {
			return openwallet.NewError(openwallet.ErrUnknownException, "cant find address:"+add+",err:"+err.Error())
		}
		msgStr := strings.TrimPrefix(msg, "0x")
		signature := openwallet.KeySignature{
			EccType: decoder.wm.Config.CurveType,
			Address: addr,
			Message: msgStr,
		}
		keySignList = append(keySignList, &signature)
	}

	rawTx.RawHex = hex.EncodeToString(rawHex)
	rawTx.Signatures[rawTx.Account.AccountID] = keySignList
	rawTx.IsBuilt = true

	return nil
}

//createRawTransaction
func (decoder *XchTransactionDecoder) createRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction, addrBalance *AddrBalance, fee string, callData string, tmpNonce *uint64) *openwallet.Error {

	var (
		accountTotalSent = decimal.Zero
		txFrom           = make([]string, 0)
		txTo             = make([]string, 0)
		keySignList      = make([]*openwallet.KeySignature, 0)
		amountStr        string
		destination      string
	)

	for k, v := range rawTx.To {
		destination = k
		amountStr = v
		break
	}

	amountDec, _ := decimal.NewFromString(amountStr)
	accountTotalSent = accountTotalSent.Add(amountDec)

	txFrom = []string{fmt.Sprintf("%s:%s", addrBalance.Address, amountStr)}
	txTo = []string{fmt.Sprintf("%s:%s", destination, amountStr)}

	feesDec, _ := decimal.NewFromString(rawTx.Fees)
	accountTotalSent = accountTotalSent.Add(feesDec)
	totalFeeDecimal, _ := decimal.NewFromString(fee)
	rawTx.Fees = totalFeeDecimal.String()
	rawTx.TxAmount = accountTotalSent.String()
	rawTx.TxFrom = txFrom
	rawTx.TxTo = txTo

	puzzleHash := EncodePuzzleHash(addrBalance.Address, decoder.wm.Config.Prefix)
	unspent, err := decoder.wm.WalletClient.GetCoinRecordsByPuzzleHash(puzzleHash, false)
	if err != nil {
		return openwallet.NewError(openwallet.ErrInsufficientBalanceOfAddress, "GetBalanceUnspent error:"+err.Error())
	}

	addr, err := wrapper.GetAddress(addrBalance.Address)
	if err != nil {
		return openwallet.NewError(openwallet.ErrAccountNotAddress, err.Error())
	}

	maxPrice, _ := decimal.NewFromString("18446744073709551615")
	if accountTotalSent.GreaterThanOrEqual(maxPrice) {
		return openwallet.NewError(openwallet.ErrAccountNotAddress, "over max 18446744073709551615")
	}

	memPoolCoins, err := decoder.wm.WalletClient.GetAllMempoolItems()
	if err != nil {
		return openwallet.NewError(openwallet.ErrUnknownException, err.Error())
	}

	//判断如果mempool存在，先不提
	if len(memPoolCoins) > 0 {
		puzzleHash := EncodePuzzleHash(addr.Address, decoder.wm.Config.Prefix)
		for _, coin := range memPoolCoins {
			if coin.PuzzleHash == puzzleHash {
				return openwallet.NewError(openwallet.ErrUnknownException, "the mempool exist: "+puzzleHash)
			}
		}
	}

	totalSentInt := uint64(accountTotalSent.Shift(decoder.wm.Decimal()).IntPart())
	feeInt := uint64(totalFeeDecimal.Shift(decoder.wm.Decimal()).IntPart())

	//生成交易结构
	rawTrans, err := decoder.wm.WalletClientIn.CreateRawTransaction("0x"+addr.PublicKey, totalSentInt, feeInt, destination, unspent.CoinRecords)
	if err != nil {
		return openwallet.NewError(openwallet.ErrUnknownException, err.Error())
	}

	rawHex, _ := json.Marshal(rawTrans)
	if rawTx.Signatures == nil {
		rawTx.Signatures = make(map[string][]*openwallet.KeySignature)
	}

	for _, msg := range rawTrans.Msg {
		msgStr := strings.TrimPrefix(msg, "0x")
		signature := openwallet.KeySignature{
			EccType: decoder.wm.Config.CurveType,
			Address: addr,
			Message: msgStr,
		}
		keySignList = append(keySignList, &signature)
	}

	rawTx.RawHex = hex.EncodeToString(rawHex)
	rawTx.Signatures[rawTx.Account.AccountID] = keySignList
	rawTx.IsBuilt = true

	return nil
}

// CreateSummaryRawTransactionWithError 创建汇总交易，返回能原始交易单数组（包含带错误的原始交易单）
func (decoder *XchTransactionDecoder) CreateSummaryRawTransactionWithError(wrapper openwallet.WalletDAI, sumRawTx *openwallet.SummaryRawTransaction) ([]*openwallet.RawTransactionWithError, error) {
	return decoder.CreateSimpleSummaryRawTransaction(wrapper, sumRawTx)
}
