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
	"github.com/imroc/req"
	"github.com/tidwall/gjson"
	"net/http"
)

type ClientIn struct {
	BaseURL            string
	Debug              bool
	APIInCrtPrivateKey string
	APIInKeyPrivateKey string
	Prefix string
}

//公钥转hash
func (c *ClientIn) GetPuzzleHashByPubKey(hash string) (string, error) {

	body := make(map[string]interface{}, 0)
	body["pub_key"] = hash
	result, err := c.Call("get_puzzle_hash_by_pub_key", body)
	if err != nil {
		return "", err
	}
	if result == nil {
		return "", errors.New("get_puzzle_hash_by_pub_key error")
	}
	data := result.Get("puzzle_hash")
	if !data.Exists() {
		return "", errors.New("get_puzzle_hash_by_pub_key error")
	}

	return data.Str, err

}

func (c *ClientIn) SyntheticSecretKey(hash string) (string, error) {

	body := make(map[string]interface{}, 0)
	body["synthetic_secret_key"] = hash
	result, err := c.Call("synthetic_secret_key", body)
	if err != nil {
		return "", err
	}
	if result == nil {
		return "", errors.New("synthetic_secret_key error")
	}
	data := result.Get("puzzle_hash")
	if !data.Exists() {
		return "", errors.New("puzzle_hash error")
	}

	return data.Str, err

}

func (c *ClientIn) GetCoinID(Coin2 *Coin) (*Coin, error) {

	CoinReq := &CoinReq{
		Coin: Coin2,
	}

	body := make(map[string]interface{}, 0)
	jsonStr, _ := json.Marshal(CoinReq)
	//s := string(jsonStr)
	json.Unmarshal(jsonStr, &body)
	result, err := c.Call("get_coin_id", body)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("get_coin_id error")
	}
	data := result.Get("coin_id")
	if !data.Exists() {
		return nil, errors.New("get_coin_id bundle error")
	}
	CoinReq.Coin.CoinID = data.String()

	return CoinReq.Coin, err

}

func (c *ClientIn) CreateSummaryRawTransaction(pubs []string, coinRecord []*CoinRecord, to string, fee uint64) (*RawTrans, error) {

	body := make(map[string]interface{}, 0)
	body["pubs"] = pubs
	body["fee"] = fee
	body["to"] = to
	body["records"] = coinRecord
	body["prefix"] = c.Prefix

	result, err := c.Call("create_raw_for_all_records", body)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("create_raw_transaction error")
	}
	data := result.Get("bundle")
	if !data.Exists() {
		return nil, errors.New("create_raw_transaction bundle error")
	}

	rawTrans := &RawTrans{}
	err = json.Unmarshal([]byte(result.Raw), rawTrans)
	if err != nil {
		return nil, errors.New("create_raw_transaction error2,json error")
	}
	return rawTrans, err

}

func (c *ClientIn) CreateRawTransaction(hash string, amount uint64, fee uint64, to string, coinRecord []*CoinRecord) (*RawTrans, error) {

	body := make(map[string]interface{}, 0)
	body["pub_key"] = hash
	body["amount"] = amount
	body["fee"] = fee
	body["to"] = to
	body["records"] = coinRecord
	body["prefix"] = c.Prefix
	result, err := c.Call("create_raw_transaction", body)
	if err != nil {
		return nil,errors.New("create_raw_transaction error:"+err.Error())
	}
	if result == nil {
		return nil, errors.New("create_raw_transaction error")
	}
	data := result.Get("bundle")
	if !data.Exists() {
		return nil, errors.New("create_raw_transaction bundle error")
	}

	rawTrans := &RawTrans{}
	err = json.Unmarshal([]byte(result.Raw), rawTrans)
	if err != nil {
		return nil, errors.New("create_raw_transaction error2,json error")
	}
	return rawTrans, err

}

func (c *ClientIn) Call(method string, params interface{}) (*gjson.Result, error) {
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
	err = isErrorIn(&resp)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

//isErrorIn 是否报错
func isErrorIn(result *gjson.Result) error {

	if !result.IsObject() {
		return fmt.Errorf("Response is empty! ")
	}

	if !result.Get("success").Bool() {
		return fmt.Errorf("api not success :%s", result.Raw)
	}

	return nil
}

func (c *ClientIn) getTLSConfig() (*tls.Config, error) {
	var _tlsConfig *tls.Config

	crtStrByte, err := base64.StdEncoding.DecodeString(c.APIInCrtPrivateKey)
	keyByte, err := base64.StdEncoding.DecodeString(c.APIInKeyPrivateKey)

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
