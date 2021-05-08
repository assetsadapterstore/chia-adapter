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
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/blocktree/openwallet/v2/log"
	"github.com/blocktree/openwallet/v2/openwallet"
	"github.com/imroc/req"
	"github.com/shopspring/decimal"
	"github.com/tidwall/gjson"
	"net/http"
)

type Client struct {
	BaseURL          string
	Debug            bool
	APICrtPrivateKey string
	APIKeyPrivateKey string
	Prefix string
}

func (c *Client) GetBlockState() (*gjson.Result, error) {
	body := make(map[string]interface{}, 0)
	result, err := c.Call("get_blockchain_state", body)
	return result, err

}

func (c *Client) GetLastBlock() (uint64, error) {
	body := make(map[string]interface{}, 0)
	result, err := c.Call("get_blockchain_state", body)
	if err != nil {
		return 0, err
	}
	if result == nil || !result.Get("blockchain_state").Exists() || !result.Get("blockchain_state").Get("peak").Exists() {
		return 0, errors.New("get_blockchain_state get error")
	}
	height := result.Get("blockchain_state").Get("peak").Get("height").Uint()   //总是获取前一个高度
	return height, err

}

func (c *Client) GetBlockByHeight(block uint64) (*Block, error) {
	body := make(map[string]interface{}, 0)
	body["height"] = block
	result, err := c.Call("get_block_record_by_height", body)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("get_block_record_by_height get error")
	}
	data := result.Get("block_record")
	if !data.Exists() {
		return nil, errors.New("get_block_record_by_height get error")
	}

	chiaBlock := &Block{}
	err = json.Unmarshal([]byte(data.Raw), chiaBlock)
	if err != nil {
		return nil, errors.New("get_block_record_by_height get error2")
	}
	return chiaBlock, err

}

func (c *Client) GetAdditionsAndRemovals(hash string) (*BlockTrans, error) {
	body := make(map[string]interface{}, 0)
	body["header_hash"] = hash
	result, err := c.Call("get_additions_and_removals", body)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("get_additions_and_removals get error")
	}
	if !result.Exists() {
		return nil, errors.New("get_additions_and_removals get error")
	}

	blockTrans := &BlockTrans{}
	err = json.Unmarshal([]byte(result.Raw), blockTrans)
	if err != nil {
		return nil, errors.New("get_additions_and_removals get error2")
	}
	blockTrans.BlockHash = hash
	return blockTrans, err

}

func (c *Client) GetBlockByHash(hash string) (*Block, error) {
	body := make(map[string]interface{}, 0)
	body["header_hash"] = hash
	result, err := c.Call("get_block_record", body)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("get_block hash get error")
	}
	data := result.Get("block_record")
	if !data.Exists() {
		return nil, errors.New("get_block hash get error")
	}
	chiaBlock := &Block{}
	err = json.Unmarshal([]byte(data.Raw), chiaBlock)
	if err != nil {
		return nil, errors.New("get_block_record_by_height get error2")
	}
	return chiaBlock, err

}

func (c *Client) GetCoinRecordByCoinID(coinID string) (*CoinRecord, error) {
	body := make(map[string]interface{}, 0)
	body["name"] = coinID
	result, err := c.Call("get_coin_record_by_name", body)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("get_coin_record_by_name")
	}
	data := result.Get("block_record")
	if !data.Exists() {
		return nil, errors.New("get_coin_record_by_name hash get error")
	}

	coinRecord := &CoinRecord{}
	err = json.Unmarshal([]byte(data.Raw), coinRecord)
	if err != nil {
		return nil, errors.New("get_coin_record_by_name get error2")
	}
	return coinRecord, err

}

func (c *Client) GetTransactionByBlockHash(blockHash string) (*gjson.Result, error) {

	body := make(map[string]interface{}, 0)
	body["header_hash"] = blockHash
	result, err := c.Call("get_block", body)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("get_block hash get error")
	}
	data := result.Get("block_record")
	if !data.Exists() {
		return nil, errors.New("get_block hash get error")
	}

	chiaBlock := &Block{}
	//chiaBlock.Height = data.Get("height").String()
	chiaBlock.BlockHash = data.Get("header_hash").String()
	chiaBlock.PreviousHash = data.Get("prev_hash").String()
	return nil, err

}

func (c *Client) GetCoinRecordsByPuzzleHash(puzzleHash string, spent bool) (*Unspent, error) {

	body := make(map[string]interface{}, 0)
	body["puzzle_hash"] = puzzleHash
	body["include_spend_coins"] = spent
	result, err := c.Call("get_coin_records_by_puzzle_hash", body)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("get_coin_records_by_puzzle_hash get error")
	}
	data := result.Get("coin_records")
	if !data.Exists() {
		return nil, errors.New("get_coin_records_by_puzzle_hash get error")
	}

	unspent := &Unspent{}
	err = json.Unmarshal([]byte(result.Raw), unspent)
	if err != nil {
		return nil, errors.New("get_coin_records_by_puzzle_hash error2,json error")
	}
	return unspent, err

}



// getUnspentBalance
func (c *Client) GetBalanceUnspentByAddresses(address []string) (decimal.Decimal,map[string]*openwallet.Balance, error) {
	puzzleHash := make([]string,0)
	balances := make(map[string]*openwallet.Balance)
	for _, a := range address{
		p :=  EncodePuzzleHash(a,c.Prefix)
		puzzleHash = append(puzzleHash,  p)
		balance := &openwallet.Balance{
			Address:a,
		}
		balances[p] = balance
	}
	unspent, err := c.GetCoinRecordsByPuzzleHashes(puzzleHash, false)
	if err != nil {
		return decimal.Zero,balances, errors.New("GetBalanceUnspentByAddresses error:" + err.Error())
	}
	if len(unspent.CoinRecords) > 0 {
		balance := decimal.Zero
		for _, c := range unspent.CoinRecords {
			d, _ := decimal.NewFromString(c.Coin.Amount.String())

			nowAmount,_ := decimal.NewFromString(balances[c.Coin.PuzzleHash].Balance)
			nowAmount = nowAmount.Add(d)
			balances[c.Coin.PuzzleHash].Balance = nowAmount.String()
			balance = balance.Add(d)
		}
		return balance,balances, nil
	}
	return decimal.Zero,balances, nil
}


func (c *Client) GetCoinRecordsByPuzzleHashes(puzzleHash []string, spent bool) (*Unspent, error) {

	body := make(map[string]interface{}, 0)
	body["puzzle_hashes"] = puzzleHash
	body["include_spend_coins"] = spent
	result, err := c.Call("get_coin_records_by_puzzle_hashes", body)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("get_coin_records_by_puzzle_hashes get error")
	}
	data := result.Get("coin_records")
	if !data.Exists() {
		return nil, errors.New("get_coin_records_by_puzzle_hashes get error")
	}

	unspent := &Unspent{}
	err = json.Unmarshal([]byte(result.Raw), unspent)
	if err != nil {
		return nil, errors.New("get_coin_records_by_puzzle_hashes error2,json error")
	}
	return unspent, err

}

// getUnspentBalance
func (c *Client) GetBalanceUnspent(address string) (decimal.Decimal, error) {
	puzzleHash := EncodePuzzleHash(address,c.Prefix)
	unspent, err := c.GetCoinRecordsByPuzzleHash(puzzleHash, false)
	if err != nil {
		return decimal.Zero, errors.New("GetBalanceUnspent error:" + err.Error())
	}
	if len(unspent.CoinRecords) > 0 {
		balance := decimal.Zero
		for _, c := range unspent.CoinRecords {
			d, _ := decimal.NewFromString(c.Coin.Amount.String())
			balance = balance.Add(d)
		}
		return balance, nil
	}
	return decimal.Zero, nil
}

// getUnspentBalance
func (c *Client) GetCoinRecorde(address string) (decimal.Decimal, error) {
	puzzleHash := EncodePuzzleHash(address,c.Prefix)
	unspent, err := c.GetCoinRecordsByPuzzleHash(puzzleHash, false)
	if err != nil {
		return decimal.Zero, errors.New("GetBalanceUnspent error:" + err.Error())
	}
	if len(unspent.CoinRecords) > 0 {
		balance := decimal.Zero
		for _, c := range unspent.CoinRecords {
			d, _ := decimal.NewFromString(c.Coin.Amount.String())
			balance = balance.Add(d)
		}
		return balance, nil
	}
	return decimal.Zero, nil
}

// getUnspentBalance
func (c *Client) PutTx(Bundle *SendTrans) (bool, error) {
	body2 := make(map[string]interface{})
	jsonStr, _ := json.Marshal(Bundle)
	s := string(jsonStr)
	err := json.Unmarshal([]byte(s), &body2)
	if err != nil {
		return false, errors.New("PutTx json error:" + err.Error())
	}
	result, err := c.Call("push_tx", body2)
	if err != nil {
		return false, err
	}
	if result.Get("status").String() == "SUCCESS" {
		return true, nil
	}
	return false, nil
}

// getUnspentBalance
func (c *Client) GetAllMempoolItems() ([]*Coin, error) {
	body2 := make(map[string]interface{})

	coins := make([]*Coin,0)
	result, err := c.Call("get_all_mempool_items", body2)
	if err != nil {
		return coins, err
	}
	if result.Get("mempool_items").Exists() {
		body3 := make(map[string]*Mempool)
		err :=json.Unmarshal([]byte(result.Get("mempool_items").Raw), &body3)
		if err == nil{
			if len(body3) > 0{
				for _,mem := range body3{
					coins = append(coins, mem.Removals...)
				}
			}
		}
		return coins, err
	}
	return coins, nil
}



// getUnspentBalance
func (c *Client) GetMempoolByTxID(txID string) ([]*Coin,[]*Coin, error) {
	body2 := make(map[string]interface{})
	body2["tx_id"] = txID
	coins := make([]*Coin,0)
	coin2s := make([]*Coin,0)
	result, err := c.Call("get_all_mempool_items", body2)
	if err != nil {
		return coins,coin2s, err
	}
	if result.Get("mempool_items").Exists() {
		body3 := make(map[string]*Mempool)
		err :=json.Unmarshal([]byte(result.Get("mempool_items").Raw), &body3)
		if err == nil{
			if len(body3) > 0{
				for _,mem := range body3{
					coins = append(coins, mem.Additions...)
					coin2s = append(coin2s, mem.Removals...)
				}
			}
		}
		return coins,coin2s, err
	}
	return coins,coin2s, nil
}


// getSpentBalance
func (c *Client) GetBalanceSpent(address string) (decimal.Decimal, error) {
	puzzleHash := EncodePuzzleHash(address,c.Prefix)
	unspent, err := c.GetCoinRecordsByPuzzleHash(puzzleHash, true)
	if err != nil {
		return decimal.Zero, errors.New("GetBalanceSpent error:" + err.Error())
	}
	if len(unspent.CoinRecords) > 0 {
		balance := decimal.Zero
		for _, c := range unspent.CoinRecords {
			d, _ := decimal.NewFromString(c.Coin.Amount.String())
			balance = balance.Add(d)
		}
		return balance, nil
	}
	return decimal.Zero, nil

}

func (c *Client) Call(method string, params interface{}) (*gjson.Result, error) {
	authHeader := req.Header{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	ssl, _ := c.getTLSConfig()

	req.Client().Transport = &http.Transport{
		TLSClientConfig: ssl,
	}
	r, err := req.Post(c.BaseURL+"/"+method, req.BodyJSON(&params), authHeader)

	if c.Debug {
		log.Debugf("%+v\n", r)
	}

	if err != nil {
		return nil, err
	}

	resp := gjson.ParseBytes(r.Bytes())
	err = isError(&resp)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

//isError 是否报错
func isError(result *gjson.Result) error {

	if !result.IsObject() {
		return fmt.Errorf("Response is empty! ")
	}

	if !result.Get("success").Bool() {
		return fmt.Errorf("api not success :%s", result.Raw)
	}

	return nil
}

func (c *Client) getTLSConfig() (*tls.Config, error) {
	var _tlsConfig *tls.Config

	crtStrByte, err := base64.StdEncoding.DecodeString(c.APICrtPrivateKey)
	keyByte, err := base64.StdEncoding.DecodeString(c.APIKeyPrivateKey)

	cert, err := tls.X509KeyPair(crtStrByte, keyByte)
	if err != nil {
		log.Infof("load cert keys fail", err)
		return nil, err
	}

	_tlsConfig = &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}
	return _tlsConfig, nil
}
