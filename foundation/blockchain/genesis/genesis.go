package genesis

import (
	"encoding/json"
	"os"
	"time"
)

// read the genesis.json file and mapping it to a go struct

// Genesis struct is the struct that represents the genesis.json file
type Genesis struct {
	Date          time.Time         `json:"date"`
	ChainID       int16             `json:"chain_id"`
	TransPerBlock int16             `json:"trans_per_block"`
	Difficulty    int16             `json:"difficulty"`
	MiningReward  int64             `json:"mining_reward"`
	GasPrice      int64             `json:"gas_price"`
	Balances      map[string]uint64 `json:"balances"`
}

// Load open and consume the genesis.json file
func Load() (Genesis, error) {
	// read the genesis.json file
	path := "zblock/genesis.json"
	content, err := os.ReadFile(path)
	if err != nil {
		return Genesis{}, err
	}
	// unmarshal the json file to a Genesis struct
	var genesis Genesis
	err = json.Unmarshal(content, &genesis)
	if err != nil {
		return Genesis{}, err
	}

	return genesis, nil
}
