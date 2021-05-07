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
	"github.com/blocktree/go-owcrypt"
	"github.com/blocktree/openwallet/v2/common/file"
	"path/filepath"
	"strings"
)

const (
	Symbol    = "XCH"
	CurveType = owcrypt.ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG
)

type WalletConfig struct {

	//币种
	Symbol string
	//本地数据库文件路径
	DBPath string
	//钱包服务API
	ServerAPI string

	//内部服务API
	ServerAPIIn string

	//曲线类型
	CurveType uint32
	//网络ID
	ChainID uint64
	//数据目录
	DataDir string

	//nonce计算方式, 0: auto-increment nonce, 1: latest nonce
	NonceComputeMode int64

	Prefix string

	Fee string

	SummaryFee string

	//最大unSpent数
	MaxUnSpentCount int64

	APICrtPrivateKey string
	APIKeyPrivateKey string

	APIInCrtPrivateKey string
	APIInKeyPrivateKey string

}

func NewConfig(symbol string) *WalletConfig {
	c := WalletConfig{}
	c.Symbol = symbol
	c.CurveType = CurveType
	return &c
}

//创建文件夹
func (wc *WalletConfig) makeDataDir() {

	if len(wc.DataDir) == 0 {
		//默认路径当前文件夹./data
		wc.DataDir = "data"
	}

	//本地数据库文件路径
	wc.DBPath = filepath.Join(wc.DataDir, strings.ToLower(wc.Symbol), "db")

	//创建目录
	file.MkdirAll(wc.DBPath)
}
