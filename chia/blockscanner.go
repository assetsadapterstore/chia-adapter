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
	"encoding/json"
	"github.com/blocktree/openwallet/v2/openwallet"
	"github.com/shopspring/decimal"
	"strings"
	"time"

	"fmt"
)

const (
	//BLOCK_CHAIN_BUCKET = "blockchain" //区块链数据集合
	//periodOfTask      = 5 * time.Second //定时任务执行隔间
	MAX_EXTRACTING_SIZE = 15 //并发的扫描线程数

)

type BlockScanner struct {
	*openwallet.BlockScannerBase
	CurrentBlockHeight   uint64         //当前区块高度
	extractingCH         chan struct{}  //扫描工作令牌
	wm                   *WalletManager //钱包管理者
	IsScanMemPool        bool           //是否扫描交易池
	RescanLastBlockCount uint64         //重扫上N个区块数量
}

//ExtractResult 扫描完成的提取结果
type ExtractResult struct {
	extractData         map[string][]*openwallet.TxExtractData
	extractContractData map[string]*openwallet.SmartContractReceipt
	TxID                string
	BlockHeight         uint64
	Success             bool
}

//SaveResult 保存结果
type SaveResult struct {
	TxID        string
	BlockHeight uint64
	Success     bool
}

//NewBTCBlockScanner 创建区块链扫描器
func NewBlockScanner(wm *WalletManager) *BlockScanner {
	bs := BlockScanner{
		BlockScannerBase: openwallet.NewBlockScannerBase(),
	}

	bs.extractingCH = make(chan struct{}, MAX_EXTRACTING_SIZE)
	bs.wm = wm
	bs.IsScanMemPool = false
	bs.RescanLastBlockCount = 5

	//设置扫描任务
	bs.SetTask(bs.ScanBlockTask)

	return &bs
}

//SetRescanBlockHeight 重置区块链扫描高度
func (bs *BlockScanner) SetRescanBlockHeight(height uint64) error {
	height = height - 1
	if height < 0 {
		return fmt.Errorf("block height to rescan must greater than 0 ")
	}

	block, err := bs.wm.WalletClient.GetBlockByHeight(height)
	if err != nil {
		bs.wm.Log.Errorf("get block spec by block number[%v] failed, err=%v", height, err)
		return err
	}

	err = bs.SaveLocalBlockHead(height, block.BlockHash)
	if err != nil {
		bs.wm.Log.Errorf("save local block scanned failed, err=%v", err)
		return err
	}

	return nil
}

func (bs *BlockScanner) newBlockNotify(block *Block, isFork bool) {
	var header = &openwallet.BlockHeader{
		Hash:              block.BlockHash,
		Previousblockhash: block.PreviousHash,
		Height:            block.Height,
		Time:              uint64(time.Now().Unix()),
	}
	header.Fork = isFork
	header.Symbol = bs.wm.Config.Symbol
	bs.NewBlockNotify(header)
}

func (bs *BlockScanner) ScanBlock(height uint64) error {
	curBlock, err := bs.wm.WalletClient.GetBlockByHeight(height)
	if err != nil {
		bs.wm.Log.Errorf("XchGetBlockSpecByBlockNum failed, err = %v", err)
		return err
	}
	blockTrans, err := bs.wm.WalletClient.GetAdditionsAndRemovals(curBlock.BlockHash)
	if err != nil {
		bs.wm.Log.Errorf("block scanner can not GetAdditionsAndRemovals; unexpected error: %v", err)
		return err
	}
	err = bs.BatchExtractTransaction(height, blockTrans)
	if err != nil {
		bs.wm.Log.Errorf("BatchExtractTransaction failed, err = %v", err)
		return err
	}

	bs.newBlockNotify(curBlock, false)

	return nil
}

//rescanFailedRecord 重扫失败记录
func (bs *BlockScanner) RescanFailedRecord() {

	var (
		blockMap = make(map[uint64][]string)
	)

	list, err := bs.GetUnscanRecords()
	if err != nil {
		bs.wm.Log.Std.Info("block scanner can not get rescan data; unexpected error: %v", err)
	}

	//组合成批处理
	for _, r := range list {

		if _, exist := blockMap[r.BlockHeight]; !exist {
			blockMap[r.BlockHeight] = make([]string, 0)
		}

		if len(r.TxID) > 0 {
			arr := blockMap[r.BlockHeight]
			arr = append(arr, r.TxID)

			blockMap[r.BlockHeight] = arr
		}
	}

	for height, _ := range blockMap {

		if height == 0 {
			continue
		}

		bs.wm.Log.Std.Info("block scanner rescanning height: %d ...", height)

		block, err := bs.wm.WalletClient.GetBlockByHeight(height)
		if err != nil {
			bs.wm.Log.Std.Info("block scanner can not get new block data; unexpected error: %v", err)
			continue
		}

		blockTrans, err := bs.wm.WalletClient.GetAdditionsAndRemovals(block.BlockHash)
		if err != nil {
			bs.wm.Log.Errorf("block scanner can not GetAdditionsAndRemovals; unexpected error: %v", err)
			continue
		}
		batchErr := bs.BatchExtractTransaction(block.Height, blockTrans)
		if batchErr != nil {
			bs.wm.Log.Std.Info("block scanner can not extractRechargeRecords; unexpected error: %v", batchErr)
			continue
		}

		//删除未扫记录
		bs.DeleteUnscanRecord(height)
	}
}

func (bs *BlockScanner) ScanBlockTask() {

	//获取本地区块高度
	blockHeader, err := bs.GetScannedBlockHeader()
	if err != nil {
		bs.wm.Log.Errorf("block scanner can not get new block height; unexpected error: %v", err)
		return
	}

	curBlockHeight := blockHeader.Height
	curBlockHash := blockHeader.Hash
	var previousHeight uint64 = 0
	for {

		if !bs.Scanning {
			//区块扫描器已暂停，马上结束本次任务
			return
		}

		maxBlockHeight, err := bs.wm.WalletClient.GetLastBlock()
		if err != nil {
			bs.wm.Log.Errorf("get max height of eth failed, err=%v", err)
			break
		}

		bs.wm.Log.Info("current block height:", curBlockHeight, " maxBlockHeight:", maxBlockHeight)
		if curBlockHeight >= maxBlockHeight {
			bs.wm.Log.Infof("block scanner has done with scan. current height:%v", maxBlockHeight)
			break
		}

		//扫描下一个区块
		curBlockHeight += 1
		bs.wm.Log.Infof("block scanner try to scan block No.%v", curBlockHeight)

		curBlock, err := bs.wm.WalletClient.GetBlockByHeight(curBlockHeight)
		if err != nil {
			bs.wm.Log.Errorf("XchGetBlockSpecByBlockNum failed, err = %v", err)
			break
		}

		isFork := false

		if curBlock == nil {
			bs.wm.Log.Errorf("XchGetBlockSpecByBlockNum failed,curBlock is nil", err)
			break
		}

		if curBlock.PreviousHash != curBlockHash {
			previousHeight = curBlockHeight - 1
			bs.wm.Log.Infof("block has been fork on height: %v.", curBlockHeight)
			bs.wm.Log.Infof("block height: %v local hash = %v ", previousHeight, curBlockHash)
			bs.wm.Log.Infof("block height: %v mainnet hash = %v ", previousHeight, curBlock.PreviousHash)

			bs.wm.Log.Infof("delete recharge records on block height: %v.", previousHeight)

			//查询本地分叉的区块
			forkBlock, _ := bs.GetLocalBlock(previousHeight)

			bs.DeleteUnscanRecord(previousHeight)

			curBlockHeight = previousHeight - 1 //倒退2个区块重新扫描

			curBlock, err = bs.GetLocalBlock(curBlockHeight)
			if err != nil {
				bs.wm.Log.Std.Error("block scanner can not get local block; unexpected error: %v", err)
				bs.wm.Log.Info("block scanner prev block height:", curBlockHeight)

				curBlock, err = bs.wm.WalletClient.GetBlockByHeight(curBlockHeight)
				if err != nil {
					bs.wm.Log.Errorf("XchGetBlockSpecByBlockNum  failed, block number=%v, err=%v", curBlockHeight, err)
					break
				}

			}

			curBlockHash = curBlock.BlockHash
			bs.wm.Log.Infof("rescan block on height:%v, hash:%v.", curBlockHeight, curBlockHash)

			err = bs.SaveLocalBlockHead(curBlock.Height, curBlock.BlockHash)
			if err != nil {
				bs.wm.Log.Errorf("save local block unscaned failed, err=%v", err)
				break
			}

			isFork = true

			if forkBlock != nil {

				//通知分叉区块给观测者，异步处理
				bs.newBlockNotify(forkBlock, isFork)
			}

		} else {

			blockTrans, err := bs.wm.WalletClient.GetAdditionsAndRemovals(curBlockHash)
			if err != nil {
				bs.wm.Log.Errorf("block scanner can not GetAdditionsAndRemovals; unexpected error: %v", err)
				break
			}
			err = bs.BatchExtractTransaction(curBlock.Height, blockTrans)
			if err != nil {
				bs.wm.Log.Errorf("block scanner can not extractRechargeRecords; unexpected error: %v", err)
				break
			}

			bs.SaveLocalBlockHead(curBlock.Height, curBlock.BlockHash)
			bs.SaveLocalBlock(curBlock)

			isFork = false

			bs.newBlockNotify(curBlock, isFork)
		}

		curBlockHeight = curBlock.Height
		curBlockHash = curBlock.BlockHash

	}

	//重扫前N个块，为保证记录找到
	for i := curBlockHeight - bs.RescanLastBlockCount; i <= curBlockHeight; i++ {
		bs.scanBlock(i)
	}

	bs.RescanFailedRecord()
}


func (bs *BlockScanner) scanBlock(height uint64)  error {

	curBlock, err := bs.wm.WalletClient.GetBlockByHeight(height)
	if err != nil {
		bs.wm.Log.Errorf("XchGetBlockSpecByBlockNum failed, err = %v", err)
		return err
	}
	blockTrans, err := bs.wm.WalletClient.GetAdditionsAndRemovals(curBlock.BlockHash)
	if err != nil {
		bs.wm.Log.Errorf("block scanner can not GetAdditionsAndRemovals; unexpected error: %v", err)
		return err
	}
	err = bs.BatchExtractTransaction(height, blockTrans)
	if err != nil {
		bs.wm.Log.Errorf("BatchExtractTransaction failed, err = %v", err)
		return err
	}

	return  nil
}

//newExtractDataNotify 发送通知
func (bs *BlockScanner) newExtractDataNotify(height uint64, extractDataList map[string][]*openwallet.TxExtractData, extractContractData map[string]*openwallet.SmartContractReceipt) error {

	for o, _ := range bs.Observers {
		for key, extractData := range extractDataList {
			for _, data := range extractData {
				err := o.BlockExtractDataNotify(key, data)
				if err != nil {
					//记录未扫区块
					reason := fmt.Sprintf("ExtractData Notify failed: %s", bs.wm.Symbol())
					err = bs.SaveUnscannedTransaction(height, reason)
					if err != nil {
						bs.wm.Log.Errorf("block height: %d, save unscan record failed. unexpected error: %v", height, err.Error())
						return err
					}
				}
			}
		}

		for key, data := range extractContractData {
			err := o.BlockExtractSmartContractDataNotify(key, data)
			if err != nil {
				//记录未扫区块
				reason := fmt.Sprintf("ExtractContractData Notify failed: %s", bs.wm.Symbol())
				err = bs.SaveUnscannedTransaction(height, reason)
				if err != nil {
					bs.wm.Log.Errorf("block height: %d, save unscan record failed. unexpected error: %v", height, err.Error())
					return err
				}
			}
		}
	}

	return nil
}

//BatchExtractTransaction 批量提取交易单
func (bs *BlockScanner) BatchExtractTransaction(height uint64, txs *BlockTrans) error {

	var (
		quit   = make(chan struct{})
		done   = 0 //完成标记
		failed = 0
		//shouldDone = len(txs) //需要完成的总数
	)

	if txs == nil || (len(txs.Additions) == 0 && len(txs.Removals) == 0) {
		return nil
	}

	records := txs.GetCoinRecord()
	shouldDone := len(records)
	//生产通道
	producer := make(chan ExtractResult)
	defer close(producer)

	//消费通道
	worker := make(chan ExtractResult)
	defer close(worker)

	//保存工作
	saveWork := func(height uint64, result chan ExtractResult) {
		//回收创建的地址
		for gets := range result {

			if gets.Success {

				notifyErr := bs.newExtractDataNotify(height, gets.extractData, gets.extractContractData)
				//saveErr := bs.SaveRechargeToWalletDB(height, gets.Recharges)
				if notifyErr != nil {
					failed++ //标记保存失败数
					bs.wm.Log.Std.Info("newExtractDataNotify unexpected error: %v", notifyErr)
				}

			} else {
				//记录未扫区块
				unscanRecord := openwallet.NewUnscanRecord(height, "", "", bs.wm.Symbol())
				bs.SaveUnscanRecord(unscanRecord)
				bs.wm.Log.Std.Info("block height: %d extract failed.", height)
				failed++ //标记保存失败数
			}
			//累计完成的线程数
			done++
			if done == shouldDone {
				//bs.wm.Log.Std.Info("done = %d, shouldDone = %d ", done, len(txs))
				close(quit) //关闭通道，等于给通道传入nil
			}
		}
	}

	//提取工作
	extractWork := func(mTxs []*CoinRecord, eProducer chan ExtractResult) {
		for _, tx := range mTxs {
			bs.extractingCH <- struct{}{}
			//shouldDone++
			go func(mTx *CoinRecord, end chan struct{}, mProducer chan<- ExtractResult) {
				mTx.FilterFunc = bs.ScanTargetFuncV2
				//mTx.ConfirmedBlockIndex = height

				//导出提出的交易
				mProducer <- bs.ExtractTransaction(mTx)
				//释放
				<-end

			}(tx, bs.extractingCH, eProducer)
		}
	}

	/*	开启导出的线程	*/

	//独立线程运行消费
	go saveWork(height, worker)

	//独立线程运行生产
	go extractWork(records, producer)

	//以下使用生产消费模式
	bs.extractRuntime(producer, worker, quit)

	if failed > 0 {
		return fmt.Errorf("block scanner saveWork failed")
	} else {
		return nil
	}

	//return nil
}

//extractRuntime 提取运行时
func (bs *BlockScanner) extractRuntime(producer chan ExtractResult, worker chan ExtractResult, quit chan struct{}) {

	var (
		values = make([]ExtractResult, 0)
	)

	for {

		var activeWorker chan<- ExtractResult
		var activeValue ExtractResult

		//当数据队列有数据时，释放顶部，传输给消费者
		if len(values) > 0 {
			activeWorker = worker
			activeValue = values[0]

		}

		select {

		//生成者不断生成数据，插入到数据队列尾部
		case pa := <-producer:
			values = append(values, pa)
		case <-quit:
			//退出
			//bs.wm.Log.Std.Info("block scanner have been scanned!")
			return
		case activeWorker <- activeValue:
			//wm.Log.Std.Info("Get %d", len(activeValue))
			values = values[1:]
		}
	}

}

// GetBalanceByAddress 获取地址余额
func (bs *BlockScanner) GetBalanceByAddress(address ...string) ([]*openwallet.Balance, error) {

	balances := make([]*openwallet.Balance, 0)




	_, resultBalance, err := bs.wm.WalletClient.GetBalanceUnspentByAddresses(address)
	if err != nil {
		return nil, err
	}

	for _, v := range resultBalance {
		amount, _ := decimal.NewFromString(v.Balance)
		amount = amount.Shift(-bs.wm.Decimal())
		v.Balance = amount.String()
		v.ConfirmBalance = amount.String()
		v.UnconfirmBalance = decimal.Zero.String()
		balances = append(balances, v)
		bs.wm.Log.Warn("Balance Get Transaction. current to:%v",v.Address,",balance:",v.Balance)
	}

	return balances, nil
}

// ExtractTransaction 提取交易单
func (bs *BlockScanner) ExtractTransaction(tx *CoinRecord) ExtractResult {

	var (
		result = ExtractResult{
			BlockHeight:         tx.ConfirmedBlockIndex,
			extractData:         make(map[string][]*openwallet.TxExtractData),
			extractContractData: make(map[string]*openwallet.SmartContractReceipt),
			Success:             true,
		}
	)

	if tx.ConfirmedBlockIndex == 0 {
		result.Success = false
		return result
	}

	// 提取转账交易单
	bs.extractBaseTransaction(tx, &result)

	return result
}

// extractBaseTransaction 提取转账交易单
func (bs *BlockScanner) extractBaseTransaction(tx *CoinRecord, result *ExtractResult) {

	//提出主币交易单
	extractData := bs.extractTransaction(tx)
	for sourceKey, data := range extractData {
		extractDataArray := result.extractData[sourceKey]
		if extractDataArray == nil {
			extractDataArray = make([]*openwallet.TxExtractData, 0)
		}
		extractDataArray = append(extractDataArray, data)
		result.extractData[sourceKey] = extractDataArray
	}

}

//extractXCHTransaction 提取主币交易单
func (bs *BlockScanner) extractTransaction(tx *CoinRecord) map[string]*openwallet.TxExtractData {

	txExtractMap := make(map[string]*openwallet.TxExtractData)
	from := tx.Coin.CoinID
	to := tx.Coin.CoinID
	if tx.Type == 1 {
		to = DecodePuzzleHash(tx.Coin.PuzzleHash, bs.wm.Config.Prefix)
	} else if tx.Type == 2 {
		from = DecodePuzzleHash(tx.Coin.PuzzleHash, bs.wm.Config.Prefix)
	}
	status := "1"
	nowUnix := time.Now().Unix()
	txType := uint64(0)

	coin := openwallet.Coin{
		Symbol:     bs.wm.Symbol(),
		IsContract: false,
	}

	amount, _ := decimal.NewFromString(tx.Coin.Amount.String())

	ethAmount := amount.Shift(-bs.wm.Decimal()).String()

	//提现
	//if tx.Type == 2 {
	//	targetResult := tx.FilterFunc(openwallet.ScanTargetParam{
	//		ScanTarget:     from,
	//		Symbol:         bs.wm.Symbol(),
	//		ScanTargetType: openwallet.ScanTargetTypeAccountAddress})
	//	if targetResult.Exist {
	//		newCoin, err := bs.wm.WalletClientIn.GetCoinID(tx.Coin)
	//		if err != nil {
	//			bs.wm.Log.Error("get coinID FAIL[", tx.Coin.ParentCoinInfo, "] balance failed, err=", err)
	//		} else {
	//			to =  tx.Coin.CoinID
	//			txID := tx.Coin.CoinID + "-2"
	//			tx.Coin = newCoin
	//			input := &openwallet.TxInput{}
	//			input.TxID = txID
	//			input.Address = from
	//			input.Amount = ethAmount
	//			input.Coin = coin
	//			input.Index = 0
	//			input.Sid = openwallet.GenTxInputSID(tx.Coin.CoinID, bs.wm.Symbol(), "", 0)
	//			input.CreateAt = nowUnix
	//			input.BlockHeight = tx.SpentBlockIndex
	//			input.BlockHash = tx.BlockHash
	//			input.TxType = txType
	//
	//			//transactions = append(transactions, &transaction)
	//
	//			ed := txExtractMap[targetResult.SourceKey]
	//			if ed == nil {
	//				ed = openwallet.NewBlockExtractData()
	//				txExtractMap[targetResult.SourceKey] = ed
	//			}
	//
	//			ed.TxInputs = append(ed.TxInputs, input)
	//			txIn := &openwallet.Transaction{
	//				Fees:        "",
	//				Coin:        coin,
	//				BlockHash:   tx.BlockHash,
	//				BlockHeight: tx.ConfirmedBlockIndex,
	//				TxID:        txID,
	//				Decimal:     bs.wm.Decimal(),
	//				Amount:      ethAmount,
	//				ConfirmTime: nowUnix,
	//				From:        []string{from + ":" + ethAmount},
	//				To:          []string{to + ":" + ethAmount},
	//				Status:      status,
	//				//Reason:      reason,
	//				TxType: txType,
	//			}
	//
	//			wxID := openwallet.GenTransactionWxID(txIn)
	//			txIn.WxID = wxID
	//			txExtractMap[targetResult.SourceKey].Transaction = txIn
	//		}
	//	}
	//}



	//充值
	if tx.Type == 1 {
		//获取coinID
		newCoin, err := bs.wm.WalletClientIn.GetCoinID(tx.Coin)
		if err != nil {
			bs.wm.Log.Error("get coinID FAIL[", tx.Coin.ParentCoinInfo, "] balance failed, err=", err)
			return txExtractMap
		}

		//isWithdraw := false

		from = newCoin.CoinID

		scanType := openwallet.ScanTargetTypeAccountAddress
		targetResult2 := tx.FilterFunc(openwallet.ScanTargetParam{
			ScanTarget:     to,
			Symbol:         bs.wm.Symbol(),
			ScanTargetType: uint64(scanType)})

		// 直接判断是否本地缓存数据
		transactions, err := bs.GetTransaction(newCoin.CoinID)
		if err == nil {
			//isWithdraw = true
			if len(transactions) > 0 {
				tran := transactions[0]
				tx.Coin = newCoin


				if len(tran.From) == 0 ||  len(tran.To) == 0 {
					jsons,_ := json.Marshal(tran)
					bs.wm.Log.Error(" from or to is nil:%s",jsons)
				}
				edInput := openwallet.NewBlockExtractData()
				for i,v := range tran.From{
					addresses := strings.Split(v,":")
					if len(addresses) != 2{
						bs.wm.Log.Error("addresses input from or to is nil:%s",v)
					}

					intput := &openwallet.TxInput{}
					intput.TxID = tx.Coin.CoinID
					intput.Address = addresses[0]
					from = intput.Address
					intput.Amount = addresses[1]
					intput.Coin = coin
					intput.Index = uint64(i)
					intput.Sid = openwallet.GenTxInputSID(tx.Coin.CoinID, bs.wm.Symbol(), "", uint64(i))
					intput.CreateAt = nowUnix
					intput.BlockHeight = tx.ConfirmedBlockIndex
					intput.BlockHash = tx.BlockHash
					intput.TxType = 2
					edInput.TxInputs = append(edInput.TxInputs, intput)
					//寻找找零地址
					for i2,v2 := range tran.To{
						addressesTo := strings.Split(v2,":")
						if len(addressesTo) != 2{
							bs.wm.Log.Error("addressesTo input from or to is nil:%s",v)
						}
						if addresses[0] == addressesTo[0]{
							output := &openwallet.TxOutPut{}
							output.TxID = newCoin.CoinID
							output.Address = addressesTo[0]
							output.Amount = addressesTo[1]
							output.Coin = coin
							output.Index = uint64(i)
							output.Sid = openwallet.GenTxInputSID(tx.Coin.CoinID, bs.wm.Symbol(), "", uint64(i2))
							output.CreateAt = nowUnix
							output.BlockHeight = tx.ConfirmedBlockIndex
							output.BlockHash = tx.BlockHash
							output.TxType = txType
							edInput.TxOutputs = append(edInput.TxOutputs, output)
						}
					}
				}


				//for i,v := range tran.To{
				//	addresses := strings.Split(v,":")
				//	if len(addresses) != 2{
				//		bs.wm.Log.Error("addresses output from or to is nil:%s",v)
				//	}
				//	output := &openwallet.TxOutPut{}
				//	output.TxID = newCoin.CoinID
				//	output.Address = addresses[0]
				//	output.Amount = addresses[1]
				//	output.Coin = coin
				//	output.Index = uint64(i)
				//	output.Sid = openwallet.GenTxInputSID(tx.Coin.CoinID, bs.wm.Symbol(), "", uint64(i))
				//	output.CreateAt = nowUnix
				//	output.BlockHeight = tx.ConfirmedBlockIndex
				//	output.BlockHash = tx.BlockHash
				//	output.TxType = txType
				//	edOutput.TxOutputs = append(edInput.TxOutputs, output)
				//}


				txMain := &openwallet.Transaction{
					Fees:        "",
					Coin:        coin,
					BlockHash:   tx.BlockHash,
					BlockHeight: tx.ConfirmedBlockIndex,
					TxID:        tx.Coin.CoinID,
					Decimal:     bs.wm.Decimal(),
					Amount:      ethAmount,
					ConfirmTime: nowUnix,
					From:        tran.From,
					To:          tran.To,
					Status:      status,
					//Reason:      reason,
					TxType: txType,
				}


				wxIDIn := openwallet.GenTransactionWxID(txMain)
				txMain.WxID = wxIDIn
				txExtractMap[tran.AccountID] = edInput
				txExtractMap[tran.AccountID].Transaction = txMain
				bs.wm.Log.Error("transactions finish, err=:",targetResult2.Exist)
			}

		}
		if targetResult2.Exist {
			bs.wm.Log.Error("targetResult2.Exist start")
				tx.Coin = newCoin
				output := &openwallet.TxOutPut{}
				output.TxID = newCoin.CoinID
				output.Address = to
				output.Amount = ethAmount
				output.Coin = coin
				output.Index = 0
				output.Sid = openwallet.GenTxInputSID(tx.Coin.CoinID, bs.wm.Symbol(), "", 0)
				output.CreateAt = nowUnix
				output.BlockHeight = tx.ConfirmedBlockIndex
				output.BlockHash = tx.BlockHash
				output.TxType = txType



				txMain := &openwallet.Transaction{
					Fees:        "",
					Coin:        coin,
					BlockHash:   tx.BlockHash,
					BlockHeight: tx.ConfirmedBlockIndex,
					TxID:        tx.Coin.CoinID,
					Decimal:     bs.wm.Decimal(),
					Amount:      ethAmount,
					ConfirmTime: nowUnix,
					From:        []string{from + ":" + ethAmount},
					To:          []string{to + ":" + ethAmount},
					Status:      status,
					//Reason:      reason,
					TxType: txType,
				}
				wxID := openwallet.GenTransactionWxID(txMain)
				txMain.WxID = wxID
				ed := txExtractMap[targetResult2.SourceKey]
				if ed == nil {
					ed = openwallet.NewBlockExtractData()
					txExtractMap[targetResult2.SourceKey] = ed
				}
			    ed.TxOutputs = append(ed.TxOutputs, output)
				txExtractMap[targetResult2.SourceKey].Transaction = txMain
			bs.wm.Log.Error("targetResult2.Exist start end :",txExtractMap[targetResult2.SourceKey])

			}


	}

	return txExtractMap
}

//ExtractTransactionData 扫描一笔交易
func (bs *BlockScanner) ExtractTransactionData(txid string, scanTargetFunc openwallet.BlockScanTargetFunc) (map[string][]*openwallet.TxExtractData, error) {
	//result := bs.ExtractTransaction(0, "", txid, scanAddressFunc)
	tx, err := bs.wm.WalletClient.GetCoinRecordByCoinID(txid)
	if err != nil {
		bs.wm.Log.Errorf("get transaction by has failed, err=%v", err)
		return nil, fmt.Errorf("get transaction by has failed, err=%v", err)
	}
	if tx.Spent {
		tx.Type = 2
	} else {
		tx.Type = 1
	}
	tx.FilterFunc = func(target openwallet.ScanTargetParam) openwallet.ScanTargetResult {
		sourceKey, ok := scanTargetFunc(openwallet.ScanTarget{
			Address:          target.ScanTarget,
			Symbol:           bs.wm.Symbol(),
			BalanceModelType: bs.wm.BalanceModelType(),
		})
		return openwallet.ScanTargetResult{
			SourceKey: sourceKey,
			Exist:     ok,
		}
	}
	result := bs.ExtractTransaction(tx)
	return result.extractData, nil
}

//ExtractTransactionAndReceiptData 提取交易单及交易回执数据
//@required
func (bs *BlockScanner) ExtractTransactionAndReceiptData(txid string, scanTargetFunc openwallet.BlockScanTargetFuncV2) (map[string][]*openwallet.TxExtractData, map[string]*openwallet.SmartContractReceipt, error) {
	//result := bs.ExtractTransaction(0, "", txid, scanAddressFunc)
	tx, err := bs.wm.WalletClient.GetCoinRecordByCoinID(txid)
	if err != nil {
		bs.wm.Log.Errorf("get transaction by has failed, err=%v", err)
		return nil, nil, fmt.Errorf("get transaction by has failed, err=%v", err)
	}
	if tx.Spent {
		tx.Type = 2
	} else {
		tx.Type = 1
	}
	tx.FilterFunc = scanTargetFunc
	result := bs.ExtractTransaction(tx)
	return result.extractData, result.extractContractData, nil
}

//GetScannedBlockHeader 获取当前已扫区块高度
func (bs *BlockScanner) GetScannedBlockHeader() (*openwallet.BlockHeader, error) {

	var (
		blockHeight uint64 = 0
		hash        string
		err         error
	)

	blockHeight, hash, err = bs.GetLocalBlockHead()
	if err != nil {
		bs.wm.Log.Errorf("get local new block failed, err=%v", err)
		return nil, err
	}

	//如果本地没有记录，查询接口的高度
	if blockHeight == 0 {
		blockHeight, err = bs.wm.WalletClient.GetLastBlock()
		if err != nil {
			bs.wm.Log.Errorf("XchGetBlockNumber failed, err=%v", err)
			return nil, err
		}

		//就上一个区块链为当前区块
		blockHeight = blockHeight - 1

		block, err := bs.wm.WalletClient.GetBlockByHeight(blockHeight)
		if err != nil {
			bs.wm.Log.Errorf("get block spec by block number failed, err=%v", err)
			return nil, err
		}
		hash = block.BlockHash
	}

	return &openwallet.BlockHeader{Height: blockHeight, Hash: hash}, nil
}

//GetCurrentBlockHeader 获取当前区块高度
func (bs *BlockScanner) GetCurrentBlockHeader() (*openwallet.BlockHeader, error) {

	var (
		blockHeight uint64 = 0
		hash        string
		err         error
	)

	blockHeight, err = bs.wm.WalletClient.GetLastBlock()
	if err != nil {
		bs.wm.Log.Errorf("XchGetBlockNumber failed, err=%v", err)
		return nil, err
	}

	block, err := bs.wm.WalletClient.GetBlockByHeight(blockHeight)
	if err != nil {
		bs.wm.Log.Errorf("get block spec by block number failed, err=%v", err)
		return nil, err
	}
	hash = block.BlockHash

	return &openwallet.BlockHeader{Height: blockHeight, Hash: hash}, nil
}

func (bs *BlockScanner) GetGlobalMaxBlockHeight() uint64 {

	maxBlockHeight, err := bs.wm.WalletClient.GetLastBlock()
	if err != nil {
		bs.wm.Log.Errorf("get max height of eth failed, err=%v", err)
		return 0
	}
	return maxBlockHeight
}

func (bs *BlockScanner) SaveUnscannedTransaction(blockHeight uint64, reason string) error {
	unscannedRecord := openwallet.NewUnscanRecord(blockHeight, "", reason, bs.wm.Symbol())
	return bs.SaveUnscanRecord(unscannedRecord)
}
