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
	"github.com/astaxie/beego/config"
	"github.com/blocktree/openwallet/v2/log"
	"github.com/blocktree/openwallet/v2/openwallet"
)

//FullName 币种全名
func (wm *WalletManager) FullName() string {
	return "conflux"
}

//CurveType 曲线类型
func (wm *WalletManager) CurveType() uint32 {
	return wm.Config.CurveType
}

//Symbol 币种标识
func (wm *WalletManager) Symbol() string {
	return wm.Config.Symbol
}

//小数位精度
func (wm *WalletManager) Decimal() int32 {
	return 12
}

//AddressDecode 地址解析器
func (wm *WalletManager) GetAddressDecoderV2() openwallet.AddressDecoderV2 {
	return wm.Decoder
}

//TransactionDecoder 交易单解析器
func (wm *WalletManager) GetTransactionDecoder() openwallet.TransactionDecoder {
	return wm.TxDecoder
}

//GetBlockScanner 获取区块链
func (wm *WalletManager) GetBlockScanner() openwallet.BlockScanner {
	return wm.Blockscanner
}

//LoadAssetsConfig 加载外部配置
func (wm *WalletManager) LoadAssetsConfig(c config.Configer) error {
	wm.Config.ServerAPI = c.String("serverAPI")
	wm.Config.ServerAPIIn = c.String("serverAPIIn")
	wm.Config.APICrtPrivateKey = c.String("APICrtPrivateKey")
	wm.Config.APIKeyPrivateKey= c.String("APIKeyPrivateKey")
	wm.Config.APIInCrtPrivateKey = c.String("APIInCrtPrivateKey")
	wm.Config.APIInKeyPrivateKey= c.String("APIInKeyPrivateKey")


	wm.Config.DataDir = c.String("dataDir")
	wm.Config.MaxUnSpentCount, _ = c.Int64("MaxUnSpentCount")
	if wm.Config.MaxUnSpentCount == 0{
		wm.Config.MaxUnSpentCount = 200
	}
	wm.Config.Prefix = "xch"
	Prefix := c.String("Prefix")
	if Prefix != ""{
		wm.Config.Prefix = Prefix
	}

	wm.Config.Fee = "0.000006"
	Fee := c.String("Fee")
	if Fee!=""{
		wm.Config.Fee = Fee
	}

	wm.Config.SummaryFee = "0.0001"
	SummaryFee := c.String("SummaryFee")
	if SummaryFee!=""{
		wm.Config.SummaryFee = SummaryFee
	}

	client := &Client{BaseURL: wm.Config.ServerAPI, Debug: false,APICrtPrivateKey:wm.Config.APICrtPrivateKey,APIKeyPrivateKey:wm.Config.APIKeyPrivateKey,Prefix:wm.Config.Prefix}
	clientIn := &ClientIn{BaseURL: wm.Config.ServerAPIIn, Debug: false,APIInCrtPrivateKey:wm.Config.APIInCrtPrivateKey,APIInKeyPrivateKey:wm.Config.APIInKeyPrivateKey,Prefix:wm.Config.Prefix}
	wm.WalletClient = client
	wm.WalletClientIn = clientIn


	//数据文件夹
	wm.Config.makeDataDir()

	chainID, err := c.Int64("chainID")
	if err != nil {
		//设置网络chainID
		//wm.SetNetworkChainID()
	} else {
		wm.Config.ChainID = uint64(chainID)
	}


	return nil

}

//InitAssetsConfig 初始化默认配置
func (wm *WalletManager) InitAssetsConfig() (config.Configer, error) {
	return config.NewConfigData("ini", []byte(""))
}

//GetAssetsLogger 获取资产账户日志工具
func (wm *WalletManager) GetAssetsLogger() *log.OWLogger {
	return wm.Log
}


func (wm *WalletManager) BalanceModelType() openwallet.BalanceModelType {
	return openwallet.BalanceModelTypeAddress
}
