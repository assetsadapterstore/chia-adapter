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
	"bytes"
	"github.com/blocktree/go-owcrypt"
	"github.com/blocktree/openwallet/v2/common"
	"github.com/blocktree/openwallet/v2/log"
	"github.com/blocktree/openwallet/v2/openwallet"
	"strings"
)

type WalletManager struct {
	openwallet.AssetsAdapterBase
	WalletClient            *Client                         // 节点客户端
	WalletClientIn          *ClientIn                       // 内部节点客户端
	Config                  *WalletConfig                   //钱包管理配置
	Blockscanner            openwallet.BlockScanner         //区块扫描器
	Decoder                 openwallet.AddressDecoderV2     //地址编码器
	TxDecoder               openwallet.TransactionDecoder   //交易单编码器
	Log                     *log.OWLogger                   //日志工具
}

func NewWalletManager() *WalletManager {
	wm := WalletManager{}
	wm.Config = NewConfig(Symbol)
	wm.Blockscanner = NewBlockScanner(&wm)
	wm.Decoder = NewAddressDecoderV2(&wm)
	wm.TxDecoder = NewTransactionDecoder(&wm)
	wm.Log = log.NewOWLogger(wm.Symbol())
	return &wm
}






func encodeKey(cids []string) []byte {
	buffer := new(bytes.Buffer)
	for _, c := range cids {
		// bytes.Buffer.Write() err is documented to be always nil.
		_, _ = buffer.Write([]byte(c))
	}

	newHash := owcrypt.Hash(buffer.Bytes(), 0, owcrypt.HASH_ALG_SHA256)
	return newHash
}




func AppendOxToAddress(addr string) string {
	if strings.Index(addr, "0x") == -1 {
		return "0x" + addr
	}
	return addr
}

func removeOxFromHex(value string) string {
	result := value
	if strings.Index(value, "0x") != -1 {
		result = common.Substr(value, 2, len(value))
	}
	return result
}
