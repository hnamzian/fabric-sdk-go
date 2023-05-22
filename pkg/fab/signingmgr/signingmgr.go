/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signingmgr

import (
	"bytes"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite"
	"github.com/pkg/errors"
)

// SigningManager is used for signing objects with private key
type SigningManager struct {
	cryptoProvider core.CryptoSuite
	hashOpts       core.HashOpts
	signerOpts     core.SignerOpts
}

// New Constructor for a signing manager.
// @param {BCCSP} cryptoProvider - crypto provider
// @param {Config} config - configuration provider
// @returns {SigningManager} new signing manager
func New(cryptoProvider core.CryptoSuite) (*SigningManager, error) {
	return &SigningManager{cryptoProvider: cryptoProvider, hashOpts: cryptosuite.GetSHAOpts()}, nil
}

type RemoteSignatureRequest struct {
	Data string `json:"data"`
}
type RemoteSignatureResponse struct {
	Signature string `json:"signature"`
}

func Sign(ski []byte, digest []byte) (signature []byte, err error) {
	// POST /fabric-cryptosuit/:enrollmentID/key
	keygen_url := fmt.Sprintf("http://oneof_wallet:4000/fabric-cryptosuit/key/%x/sign", string(ski))
	fmt.Printf("keygen_url: %s\n", keygen_url)

	sigReq := &RemoteSignatureRequest{
		Data: hex.EncodeToString(digest),
	}
	body, err := json.Marshal(sigReq)
	fmt.Printf("body: %s\n", body)

	// Create a HTTP post request
	postReq, err := http.NewRequest("POST", keygen_url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	// Add headers
	postReq.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(postReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	signatureResponse := &RemoteSignatureResponse{}
	err = json.Unmarshal(result, signatureResponse)
	if err != nil {
		return nil, err
	}

	// convert hex string to hex
	sighex, err := hex.DecodeString(signatureResponse.Signature)
	if err != nil {
		fmt.Println("Error decoding hex string:", err)
		return
	}

	return []byte(sighex), nil
}

// Sign will sign the given object using provided key
func (mgr *SigningManager) Sign(object []byte, key core.Key) ([]byte, error) {

	if len(object) == 0 {
		return nil, errors.New("object (to sign) required")
	}

	if key == nil {
		return nil, errors.New("key (for signing) required")
	}

	digest, err := mgr.cryptoProvider.Hash(object, mgr.hashOpts)
	if err != nil {
		return nil, err
	}
	// signature, err := mgr.cryptoProvider.Sign(key, digest, mgr.signerOpts)
	signature, err := Sign(key.SKI(), digest)
	fmt.Printf("signature: %x\n", signature)
	fmt.Printf("digest: %x\n", digest)
	if err != nil {
		return nil, err
	}
	return signature, nil
}
