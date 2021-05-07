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
	"fmt"
	"github.com/blocktree/openwallet/v2/openwallet"
)

//SaveLocalBlockHead 记录区块高度和hash到本地
func (bs *BlockScanner) SaveLocalBlockHead(blockHeight uint64, blockHash string) error {

	if bs.BlockchainDAI == nil {
		return fmt.Errorf("Blockchain DAI is not setup ")
	}

	header := &openwallet.BlockHeader{
		Hash:   blockHash,
		Height: blockHeight,
		Fork:   false,
		Symbol: bs.wm.Symbol(),
	}

	return bs.BlockchainDAI.SaveCurrentBlockHead(header)
}

//GetLocalBlockHead 获取本地记录的区块高度和hash
func (bs *BlockScanner) GetLocalBlockHead() (uint64, string, error) {

	if bs.BlockchainDAI == nil {
		return 0, "", fmt.Errorf("Blockchain DAI is not setup ")
	}

	header, err := bs.BlockchainDAI.GetCurrentBlockHead(bs.wm.Symbol())
	if err != nil {
		return 0, "", err
	}

	return header.Height, header.Hash, nil
}

//SaveLocalBlock 记录本地新区块
func (bs *BlockScanner) SaveLocalBlock(blockHeader *Block) error {

	if bs.BlockchainDAI == nil {
		return fmt.Errorf("Blockchain DAI is not setup ")
	}

	header := &openwallet.BlockHeader{
		Hash:              blockHeader.BlockHash,
		Previousblockhash: blockHeader.PreviousHash,
		Height:            blockHeader.Height,
		Symbol:            bs.wm.Symbol(),
	}

	return bs.BlockchainDAI.SaveLocalBlockHead(header)
}

//GetLocalBlock 获取本地区块数据
func (bs *BlockScanner) GetLocalBlock(height uint64) (*Block, error) {

	if bs.BlockchainDAI == nil {
		return nil, fmt.Errorf("Blockchain DAI is not setup ")
	}

	header, err := bs.BlockchainDAI.GetLocalBlockHeadByHeight(height, bs.wm.Symbol())
	if err != nil {
		return nil, err
	}

	block := &Block{
		Height:    header.Height,
		BlockHash: header.Hash,
	}

	return block, nil
}

//SaveUnscanRecord 保存交易记录到钱包数据库
func (bs *BlockScanner) SaveUnscanRecord(record *openwallet.UnscanRecord) error {

	if bs.BlockchainDAI == nil {
		return fmt.Errorf("Blockchain DAI is not setup ")
	}

	return bs.BlockchainDAI.SaveUnscanRecord(record)
}

//DeleteUnscanRecord 删除指定高度的未扫记录
func (bs *BlockScanner) DeleteUnscanRecord(height uint64) error {

	if bs.BlockchainDAI == nil {
		return fmt.Errorf("Blockchain DAI is not setup ")
	}

	return bs.BlockchainDAI.DeleteUnscanRecordByHeight(height, bs.wm.Symbol())
}

//DeleteUnscanRecordByID 删除指定的未扫记录
func (bs *BlockScanner) DeleteUnscanRecordByID(id string) error {

	if bs.BlockchainDAI == nil {
		return fmt.Errorf("Blockchain DAI is not setup ")
	}

	return bs.BlockchainDAI.DeleteUnscanRecordByID(id, bs.wm.Symbol())
}

func (bs *BlockScanner) GetUnscanRecords() ([]*openwallet.UnscanRecord, error) {

	if bs.BlockchainDAI == nil {
		return nil, fmt.Errorf("Blockchain DAI is not setup ")
	}

	return bs.BlockchainDAI.GetUnscanRecords(bs.wm.Symbol())
}


func (bs *BlockScanner) SaveTransaction(tx *openwallet.Transaction) error {

	if bs.BlockchainDAI == nil {
		return  fmt.Errorf("Blockchain DAI is not setup ")
	}

	return bs.BlockchainDAI.SaveTransaction(tx)
}

func (bs *BlockScanner) GetTransaction(txID string) ([]*openwallet.Transaction, error)  {

	if bs.BlockchainDAI == nil {
		return  nil,fmt.Errorf("Blockchain DAI is not setup ")
	}

	return bs.BlockchainDAI.GetTransactionsByTxID(txID,bs.wm.Symbol())
}


//SupportBlockchainDAI 支持外部设置区块链数据访问接口
//@optional
func (bs *BlockScanner) SupportBlockchainDAI() bool {
	return true
}
