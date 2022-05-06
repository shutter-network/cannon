// The tests require geth to run in dev mode.
// You can run geth with `SHROOT=geth_chain ../../start_geth.sh`

package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/oracle"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/shutter-network/shutter/shlib/shcrypto"
)

const nodeUrl = "http://localhost:8545"

var (
	config      = params.TestChainConfig
	genesisHash = common.HexToHash("0xd702d0441aa0045ac875b526e6ea7064e67604ef2162034a9b7260540f3e9f25")
	signer      types.Signer
	baseFee     = new(big.Int).SetUint64(1_000_000_000) // 1 GWei

	deployerKey      *ecdsa.PrivateKey
	deployerAddress  common.Address
	sequencerKey     *ecdsa.PrivateKey
	sequencerAddress common.Address
	userKey          *ecdsa.PrivateKey
	userAddress      common.Address

	contractDeployData = common.Hex2Bytes("608060405234801561001057600080fd5b5061012f806100206000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806367e0badb146037578063cd16ecbf146051575b600080fd5b603d6069565b6040516048919060c2565b60405180910390f35b6067600480360381019060639190608f565b6072565b005b60008054905090565b8060008190555050565b60008135905060898160e5565b92915050565b60006020828403121560a057600080fd5b600060ac84828501607c565b91505092915050565b60bc8160db565b82525050565b600060208201905060d5600083018460b5565b92915050565b6000819050919050565b60ec8160db565b811460f657600080fd5b5056fea2646970667358221220f8b1948f74d297fafd90786c1af95e17b6a57ed35fbb91db4ccbaaf5711c59c864736f6c63430008040033")
	contractCallData   = common.Hex2Bytes("cd16ecbf0000000000000000000000000000000000000000000000000000000000000001")

	deployEonKeyStorageData = common.Hex2Bytes("60806040523480156200001157600080fd5b5062000032620000266200006e60201b60201c565b6200007660201b60201c565b60606200004960008260016200013a60201b60201c565b506200006667ffffffffffffffff8260006200013a60201b60201c565b50506200049c565b600033905090565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050816000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b6000806001805490509050600160405180606001604052808767ffffffffffffffff1681526020018567ffffffffffffffff16815260200186815250908060018154018082558091505060019003906000526020600020906002020160009091909190915060008201518160000160006101000a81548167ffffffffffffffff021916908367ffffffffffffffff16021790555060208201518160000160086101000a81548167ffffffffffffffff021916908367ffffffffffffffff16021790555060408201518160010190805190602001906200021b9291906200027a565b50505060028167ffffffffffffffff16106200026f577f2f64d9497c8c677c995d99bcc930463dca07bfc5906e28140cbfa4222ddf402c8582866040516200026693929190620003f3565b60405180910390a15b809150509392505050565b828054620002889062000466565b90600052602060002090601f016020900481019282620002ac5760008555620002f8565b82601f10620002c757805160ff1916838001178555620002f8565b82800160010185558215620002f8579182015b82811115620002f7578251825591602001919060010190620002da565b5b5090506200030791906200030b565b5090565b5b80821115620003265760008160009055506001016200030c565b5090565b600067ffffffffffffffff82169050919050565b62000349816200032a565b82525050565b600081519050919050565b600082825260208201905092915050565b60005b838110156200038b5780820151818401526020810190506200036e565b838111156200039b576000848401525b50505050565b6000601f19601f8301169050919050565b6000620003bf826200034f565b620003cb81856200035a565b9350620003dd8185602086016200036b565b620003e881620003a1565b840191505092915050565b60006060820190506200040a60008301866200033e565b6200041960208301856200033e565b81810360408301526200042d8184620003b2565b9050949350505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806200047f57607f821691505b6020821081141562000496576200049562000437565b5b50919050565b61134a80620004ac6000396000f3fe608060405234801561001057600080fd5b506004361061007d5760003560e01c8063715018a61161005b578063715018a6146100ee5780638da5cb5b146100f8578063ada8679814610116578063f2fde38b146101465761007d565b80630cb6aaf1146100825780633f5fafa4146100b45780634e70b1dc146100d0575b600080fd5b61009c60048036038101906100979190610d0f565b610162565b6040516100ab93929190610df8565b60405180910390f35b6100ce60048036038101906100c99190610f97565b61024c565b005b6100d8610659565b6040516100e59190610ff3565b60405180910390f35b6100f6610672565b005b6101006106fa565b60405161010d919061104f565b60405180910390f35b610130600480360381019061012b919061106a565b610723565b60405161013d9190611097565b60405180910390f35b610160600480360381019061015b91906110e5565b610923565b005b6001818154811061017257600080fd5b90600052602060002090600202016000915090508060000160009054906101000a900467ffffffffffffffff16908060000160089054906101000a900467ffffffffffffffff16908060010180546101c990611141565b80601f01602080910402602001604051908101604052809291908181526020018280546101f590611141565b80156102425780601f1061021757610100808354040283529160200191610242565b820191906000526020600020905b81548152906001019060200180831161022557829003601f168201915b5050505050905083565b610254610a1b565b73ffffffffffffffffffffffffffffffffffffffff166102726106fa565b73ffffffffffffffffffffffffffffffffffffffff16146102c8576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102bf906111d0565b60405180910390fd5b60008060019050600060018267ffffffffffffffff16815481106102ef576102ee6111f0565b5b90600052602060002090600202016040518060600160405290816000820160009054906101000a900467ffffffffffffffff1667ffffffffffffffff1667ffffffffffffffff1681526020016000820160089054906101000a900467ffffffffffffffff1667ffffffffffffffff1667ffffffffffffffff16815260200160018201805461037c90611141565b80601f01602080910402602001604051908101604052809291908181526020018280546103a890611141565b80156103f55780601f106103ca576101008083540402835291602001916103f5565b820191906000526020600020905b8154815290600101906020018083116103d857829003601f168201915b50505050508152505090505b6001156106515760006001826020015167ffffffffffffffff168154811061042c5761042b6111f0565b5b90600052602060002090600202016040518060600160405290816000820160009054906101000a900467ffffffffffffffff1667ffffffffffffffff1667ffffffffffffffff1681526020016000820160089054906101000a900467ffffffffffffffff1667ffffffffffffffff1667ffffffffffffffff1681526020016001820180546104b990611141565b80601f01602080910402602001604051908101604052809291908181526020018280546104e590611141565b80156105325780601f1061050757610100808354040283529160200191610532565b820191906000526020600020905b81548152906001019060200180831161051557829003601f168201915b50505050508152505090508467ffffffffffffffff16816000015167ffffffffffffffff16116106415761056b85878460200151610a23565b935083826020019067ffffffffffffffff16908167ffffffffffffffff16815250508160018467ffffffffffffffff16815481106105ac576105ab6111f0565b5b906000526020600020906002020160008201518160000160006101000a81548167ffffffffffffffff021916908367ffffffffffffffff16021790555060208201518160000160086101000a81548167ffffffffffffffff021916908367ffffffffffffffff1602179055506040820151816001019080519060200190610634929190610c22565b5090505050505050610655565b8160200151925080915050610401565b5050505b5050565b6000600260018054905061066d919061124e565b905090565b61067a610a1b565b73ffffffffffffffffffffffffffffffffffffffff166106986106fa565b73ffffffffffffffffffffffffffffffffffffffff16146106ee576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016106e5906111d0565b60405180910390fd5b6106f86000610b5e565b565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b606060006001808154811061073b5761073a6111f0565b5b906000526020600020906002020160000160089054906101000a900467ffffffffffffffff1690505b60008167ffffffffffffffff16146108e157600060018267ffffffffffffffff1681548110610796576107956111f0565b5b90600052602060002090600202016040518060600160405290816000820160009054906101000a900467ffffffffffffffff1667ffffffffffffffff1667ffffffffffffffff1681526020016000820160089054906101000a900467ffffffffffffffff1667ffffffffffffffff1667ffffffffffffffff16815260200160018201805461082390611141565b80601f016020809104026020016040519081016040528092919081815260200182805461084f90611141565b801561089c5780601f106108715761010080835404028352916020019161089c565b820191906000526020600020905b81548152906001019060200180831161087f57829003601f168201915b50505050508152505090508367ffffffffffffffff16816000015167ffffffffffffffff16116108d45780604001519250505061091e565b8060200151915050610764565b826040517f6be0ee870000000000000000000000000000000000000000000000000000000081526004016109159190610ff3565b60405180910390fd5b919050565b61092b610a1b565b73ffffffffffffffffffffffffffffffffffffffff166109496106fa565b73ffffffffffffffffffffffffffffffffffffffff161461099f576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610996906111d0565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff161415610a0f576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610a06906112f4565b60405180910390fd5b610a1881610b5e565b50565b600033905090565b6000806001805490509050600160405180606001604052808767ffffffffffffffff1681526020018567ffffffffffffffff16815260200186815250908060018154018082558091505060019003906000526020600020906002020160009091909190915060008201518160000160006101000a81548167ffffffffffffffff021916908367ffffffffffffffff16021790555060208201518160000160086101000a81548167ffffffffffffffff021916908367ffffffffffffffff1602179055506040820151816001019080519060200190610b02929190610c22565b50505060028167ffffffffffffffff1610610b53577f2f64d9497c8c677c995d99bcc930463dca07bfc5906e28140cbfa4222ddf402c858286604051610b4a93929190610df8565b60405180910390a15b809150509392505050565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050816000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b828054610c2e90611141565b90600052602060002090601f016020900481019282610c505760008555610c97565b82601f10610c6957805160ff1916838001178555610c97565b82800160010185558215610c97579182015b82811115610c96578251825591602001919060010190610c7b565b5b509050610ca49190610ca8565b5090565b5b80821115610cc1576000816000905550600101610ca9565b5090565b6000604051905090565b600080fd5b600080fd5b6000819050919050565b610cec81610cd9565b8114610cf757600080fd5b50565b600081359050610d0981610ce3565b92915050565b600060208284031215610d2557610d24610ccf565b5b6000610d3384828501610cfa565b91505092915050565b600067ffffffffffffffff82169050919050565b610d5981610d3c565b82525050565b600081519050919050565b600082825260208201905092915050565b60005b83811015610d99578082015181840152602081019050610d7e565b83811115610da8576000848401525b50505050565b6000601f19601f8301169050919050565b6000610dca82610d5f565b610dd48185610d6a565b9350610de4818560208601610d7b565b610ded81610dae565b840191505092915050565b6000606082019050610e0d6000830186610d50565b610e1a6020830185610d50565b8181036040830152610e2c8184610dbf565b9050949350505050565b600080fd5b600080fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b610e7882610dae565b810181811067ffffffffffffffff82111715610e9757610e96610e40565b5b80604052505050565b6000610eaa610cc5565b9050610eb68282610e6f565b919050565b600067ffffffffffffffff821115610ed657610ed5610e40565b5b610edf82610dae565b9050602081019050919050565b82818337600083830152505050565b6000610f0e610f0984610ebb565b610ea0565b905082815260208101848484011115610f2a57610f29610e3b565b5b610f35848285610eec565b509392505050565b600082601f830112610f5257610f51610e36565b5b8135610f62848260208601610efb565b91505092915050565b610f7481610d3c565b8114610f7f57600080fd5b50565b600081359050610f9181610f6b565b92915050565b60008060408385031215610fae57610fad610ccf565b5b600083013567ffffffffffffffff811115610fcc57610fcb610cd4565b5b610fd885828601610f3d565b9250506020610fe985828601610f82565b9150509250929050565b60006020820190506110086000830184610d50565b92915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006110398261100e565b9050919050565b6110498161102e565b82525050565b60006020820190506110646000830184611040565b92915050565b6000602082840312156110805761107f610ccf565b5b600061108e84828501610f82565b91505092915050565b600060208201905081810360008301526110b18184610dbf565b905092915050565b6110c28161102e565b81146110cd57600080fd5b50565b6000813590506110df816110b9565b92915050565b6000602082840312156110fb576110fa610ccf565b5b6000611109848285016110d0565b91505092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b6000600282049050600182168061115957607f821691505b6020821081141561116d5761116c611112565b5b50919050565b600082825260208201905092915050565b7f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572600082015250565b60006111ba602083611173565b91506111c582611184565b602082019050919050565b600060208201905081810360008301526111e9816111ad565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600061125982610d3c565b915061126483610d3c565b9250828210156112775761127661121f565b5b828203905092915050565b7f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160008201527f6464726573730000000000000000000000000000000000000000000000000000602082015250565b60006112de602683611173565b91506112e982611282565b604082019050919050565b6000602082019050818103600083015261130d816112d1565b905091905056fea2646970667358221220153b334187937fffa1eda6feb5f37e42dc40ee15049e45f8c3c15828ff07666764736f6c63430008090033")
	insertEonKeyCalldata    = common.Hex2Bytes("3f5fafa4000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080062399e73ee9d77460d6388ede2c794274bf5f353c36ada97820d7da1204d1721404ce5f3e9655c2db6438f15d86a69573b3a213a103d34da6d7ec19d192f7f310a89c23c8b6131933992ca47c3b6d888d6ba348f9eeec7bf4c79bac0e9d43d4046079d1494829c25147b71dbc859adcdc6a7be85ec15cf8ec5a2f4c7b384391")

	batchCounterAddress          = common.HexToAddress("0000000000000000000000000000000000000200")
	batchCounterDeployedBytecode = common.Hex2Bytes("608060405234801561001057600080fd5b50600436106100415760003560e01c80631d8c311f14610046578063d09de08a14610062578063e79993f31461006c575b600080fd5b610060600480360381019061005b91906102e5565b61008a565b005b61006a610168565b005b610074610288565b6040516100819190610321565b60405180910390f35b600073ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146100f0576040517f1448d0ef00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b7f5867f9e83f14fb505a43dd58880b1de7e3b5cddbfa99bb92a15dad48b453410b60008054906101000a900467ffffffffffffffff168260405161013592919061033c565b60405180910390a1806000806101000a81548167ffffffffffffffff021916908367ffffffffffffffff16021790555050565b600073ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146101ce576040517f1448d0ef00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b7f5867f9e83f14fb505a43dd58880b1de7e3b5cddbfa99bb92a15dad48b453410b60008054906101000a900467ffffffffffffffff16600160008054906101000a900467ffffffffffffffff166102259190610394565b60405161023392919061033c565b60405180910390a160016000808282829054906101000a900467ffffffffffffffff166102609190610394565b92506101000a81548167ffffffffffffffff021916908367ffffffffffffffff160217905550565b60008054906101000a900467ffffffffffffffff1681565b600080fd5b600067ffffffffffffffff82169050919050565b6102c2816102a5565b81146102cd57600080fd5b50565b6000813590506102df816102b9565b92915050565b6000602082840312156102fb576102fa6102a0565b5b6000610309848285016102d0565b91505092915050565b61031b816102a5565b82525050565b60006020820190506103366000830184610312565b92915050565b60006040820190506103516000830185610312565b61035e6020830184610312565b9392505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600061039f826102a5565b91506103aa836102a5565b92508267ffffffffffffffff038211156103c7576103c6610365565b5b82820190509291505056fea264697066735822122068c601cd0c24bf82ab94fbd11d2e0f91998753f7a133dcf71bb7af46c407a09164736f6c63430008090033")

	eonKeyBytes    = common.Hex2Bytes("062399E73EE9D77460D6388EDE2C794274BF5F353C36ADA97820D7DA1204D1721404CE5F3E9655C2DB6438F15D86A69573B3A213A103D34DA6D7EC19D192F7F310A89C23C8B6131933992CA47C3B6D888D6BA348F9EEEC7BF4C79BAC0E9D43D4046079D1494829C25147B71DBC859ADCDC6A7BE85EC15CF8EC5A2F4C7B384391")
	eonKey         *shcrypto.EonPublicKey
	decryptionKeys []*shcrypto.EpochSecretKey
)

func init() {
	deployerKey, _ = crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000001")
	deployerAddress = crypto.PubkeyToAddress(deployerKey.PublicKey)
	sequencerKey, _ = crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000002")
	sequencerAddress = crypto.PubkeyToAddress(sequencerKey.PublicKey)
	userKey, _ = crypto.HexToECDSA("b0057716d5917badaf911b193b12b910811c1497b5bada8d7711f758981c3773")
	userAddress = crypto.PubkeyToAddress(userKey.PublicKey)

	config.BatchCounterAddress = batchCounterAddress
	// address of other contracts set after deployment in prepare

	oracle.SetNodeUrl(nodeUrl)

	// eon key and decryption keys for epoch 0 to n corresponding to the eon key inserted with
	// insertEonKeyCalldata
	eonKey = new(shcrypto.EonPublicKey)
	err := eonKey.Unmarshal(eonKeyBytes)
	if err != nil {
		panic(err)
	}
	decryptionKeysHex := []string{
		"1E474F87CDC5C95E4E895435496EB551B3995F6CFC5E85BCEF7C6A7978E307C217F8343ACFBD4A9D5B2E1F21A45C8BAB808A4F0A8C25CD4602F9DE0F6BF21ABC",
		"0005F07F07573E9180B0D246B77CB68955228F10D14787830822018AA4F74293258A362765A84AA679F5692E1506CA0EC4E89070A511736780418DF818EC59FC",
		"18AF029337074CA09B8209D8D4E79B803C291FFCBE6FC6E355EDCC05D4E89B0D2A584CD4F885CA946081AE9542497238A0DEAEAE604ED3D2AC0C46FFB9D85AC4",
		"1AF7DE9BE25E5CFEB3D4A98A84FF6E480C8EC6F2CECDD5CBFE019D9789C5DEB42E127937E8F96365DC4C26E184CC29A18967D90AB7844793C6FF4F5C9B65E288",
		"24D546A738B4D24E617E62A1500B94184797A56EA0B74D010E5A927ED55EE00D27DD5EF8B1ABB5DAA61ED80E6E5B94A5A67D171AA4CE9D0261257728C2A509ED",
		"1A7C15E03BC39E6CCEE3B9C6A45892516A9277E4ACB2E45609DA0CA78D92892D16D42AFFDC81C78534156DEF2DD6FBAD90BDAE6826148AB15B324862255F037D",
		"1E8A405828F423F4770841F1ECD71DAB988478D5F95977F51EE0F860B50D5BCD1B789DF57773805DE0D33D76A7C6607CC3E986701B0C0C46227B259567E63952",
		"25BBD96D63C8DB21880DB67299089B10D60BEC4921A2AD0E8168822221BEA51B1B21A805A95DC53C57BBEB88C8686973575A6FB31EA7A1323E5964519830BD5F",
		"1A687857763D89B4A3EFB72C2642451B38E152CB72BC9DE653A4E9DE7A9FD6E0252D262BBA84E3140AE4A755E62892771834521A58E48EF16D93A816CD901410",
		"29B40D793B85F01304F425CABC6AEA1576A30FEA274819ECC73D49E0A6EC3A0B0445B5D34FAAB7881A2FFB9D100475A85DB254B81EA639C9BD853BC79C83534C",
	}
	for _, keyHex := range decryptionKeysHex {
		keyBytes := common.Hex2Bytes(keyHex)
		key := &shcrypto.EpochSecretKey{}
		err := key.Unmarshal(keyBytes)
		if err != nil {
			panic(err)
		}
		decryptionKeys = append(decryptionKeys, key)
	}

	signer = types.LatestSigner(config)
}

func prepare(t *testing.T) *state.StateDB {
	t.Helper()

	oracle.PrefetchBlock(new(big.Int).SetUint64(0), true, nil)
	parent := types.Header{}
	err := rlp.DecodeBytes(oracle.Preimage(genesisHash), &parent)
	if err != nil {
		t.Fatal(err)
	}

	database := state.NewDatabase(parent)
	statedb, err := state.New(parent.Root, database, nil)
	if err != nil {
		t.Fatal(err)
	}

	statedb.SetBalance(deployerAddress, big.NewInt(1000000000000000000))
	statedb.SetBalance(userAddress, big.NewInt(1000000000000000000))

	statedb.SetCode(batchCounterAddress, batchCounterDeployedBytecode)

	deployEonKey(t, statedb)

	return statedb
}

func makeBatchTx(t *testing.T, batchIndex uint64, transactions []*types.Transaction) *types.Transaction {
	txBytes := [][]byte{}
	for _, tx := range transactions {
		b, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		txBytes = append(txBytes, b)
	}
	unsignedBatchTx := types.BatchTx{
		ChainID:       config.ChainID,
		DecryptionKey: decryptionKeys[batchIndex].Marshal(),
		BatchIndex:    batchIndex,
		L1BlockNumber: common.Big0,
		Timestamp:     common.Big0,
		Transactions:  txBytes,
	}
	batchTx, err := types.SignNewTx(sequencerKey, signer, &unsignedBatchTx)
	if err != nil {
		t.Fatal(err)
	}
	return batchTx
}

func deployEonKey(t *testing.T, statedb *state.StateDB) {
	t.Helper()

	unsignedDeployTx := &types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     statedb.GetNonce(deployerAddress),
		GasTipCap: common.Big0,
		GasFeeCap: big.NewInt(875000000),
		Gas:       10000000,
		To:        nil,
		Value:     common.Big0,
		Data:      deployEonKeyStorageData,
	}
	deployTx, err := types.SignNewTx(deployerKey, signer, unsignedDeployTx)
	if err != nil {
		t.Fatal(err)
	}
	deployBatchTx := makeBatchTx(t, 0, []*types.Transaction{deployTx})
	deployReceipts, _, _, err := processBatchTx(t, statedb, deployBatchTx)
	if err != nil {
		t.Fatal(err)
	}
	if len(deployReceipts) != 1 || deployReceipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatal("deplying eon key storage contract failed")
	}
	config.EonKeyBroadcastAddress = deployReceipts[0].ContractAddress

	// insert new key to eon key storage with value "0x123456789a"
	unsignedInsertTx := &types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     statedb.GetNonce(deployerAddress),
		GasTipCap: common.Big0,
		GasFeeCap: big.NewInt(875000000),
		Gas:       10000000,
		To:        &config.EonKeyBroadcastAddress,
		Value:     common.Big0,
		Data:      insertEonKeyCalldata,
	}
	insertTx, err := types.SignNewTx(deployerKey, signer, unsignedInsertTx)
	if err != nil {
		t.Fatal(err)
	}
	insertBatchTx := makeBatchTx(t, 1, []*types.Transaction{insertTx})
	insertReceipts, _, _, err := processBatchTx(t, statedb, insertBatchTx)
	if err != nil {
		t.Fatal(err)
	}
	if len(insertReceipts) != 1 || insertReceipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatal("inserting eon key to storage contract failed")
	}
}

func processBatchTx(t *testing.T, statedb *state.StateDB, batchTx *types.Transaction) (types.Receipts, []*types.Log, uint64, error) {
	t.Helper()

	if batchTx.Type() != types.BatchTxType {
		t.Fatal("got non batch tx")
	}

	parent := types.Header{
		ParentHash: common.Hash{},
		// UncleHash   common.Hash
		Coinbase: sequencerAddress,
		// Root        common.Hash
		// TxHash      common.Hash
		// ReceiptHash common.Hash
		Bloom:      types.Bloom{},
		Difficulty: common.Big1,
		Number:     common.Big0,
		GasLimit:   100000000,
		// GasUsed     uint64
		Time:      0,
		Extra:     []byte{},
		MixDigest: common.Hash{},
		Nonce:     types.BlockNonce{},

		BaseFee: baseFee,
	}
	header := types.Header{
		ParentHash: common.Hash{},
		// UncleHash   common.Hash
		Coinbase: sequencerAddress,
		// Root        common.Hash
		// TxHash      common.Hash
		// ReceiptHash common.Hash
		Bloom:      types.Bloom{},
		Difficulty: parent.Difficulty,
		Number:     new(big.Int).Add(parent.Number, big.NewInt(1)),
		GasLimit:   parent.GasLimit,
		// GasUsed     uint64
		Time:      parent.Time,
		Extra:     []byte{},
		MixDigest: common.Hash{},
		Nonce:     types.BlockNonce{},

		BaseFee: misc.CalcBaseFee(config, &parent),
	}
	vmconfig := vm.Config{NoBaseFee: true}
	bc := NewBlockChain(&parent)
	block := types.NewBlock(&header, []*types.Transaction{batchTx}, nil, nil, trie.NewStackTrie(nil))

	processor := NewStateProcessor(config, bc, bc.Engine())
	receipts, logs, gasUsed, err := processor.Process(block, statedb, vmconfig)
	return receipts, logs, gasUsed, err
}

func encryptPayload(t *testing.T, payload *types.DecryptedPayload, batchIndex uint64) []byte {
	t.Helper()

	payloadEncoded, err := rlp.EncodeToBytes(payload)
	if err != nil {
		t.Fatal(err)
	}

	epochId := shcrypto.ComputeEpochID(batchIndex)
	sigma, err := shcrypto.RandomSigma(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encryptedPayload := shcrypto.Encrypt(payloadEncoded, eonKey, epochId, sigma)

	return encryptedPayload.Marshal()
}

func TestEmptyBlock(t *testing.T) {
	statedb := prepare(t)

	parent := types.Header{
		ParentHash: common.Hash{},
		// UncleHash   common.Hash
		Coinbase: sequencerAddress,
		// Root        common.Hash
		// TxHash      common.Hash
		// ReceiptHash common.Hash
		Bloom:      types.Bloom{},
		Difficulty: common.Big1,
		Number:     common.Big0,
		GasLimit:   100000000,
		// GasUsed     uint64
		Time:      0,
		Extra:     []byte{},
		MixDigest: common.Hash{},
		Nonce:     types.BlockNonce{},

		BaseFee: baseFee,
	}
	header := types.Header{
		ParentHash: common.Hash{},
		// UncleHash   common.Hash
		Coinbase: sequencerAddress,
		// Root        common.Hash
		// TxHash      common.Hash
		// ReceiptHash common.Hash
		Bloom:      types.Bloom{},
		Difficulty: parent.Difficulty,
		Number:     new(big.Int).Add(parent.Number, big.NewInt(1)),
		GasLimit:   parent.GasLimit,
		// GasUsed     uint64
		Time:      parent.Time,
		Extra:     []byte{},
		MixDigest: common.Hash{},
		Nonce:     types.BlockNonce{},

		BaseFee: misc.CalcBaseFee(config, &parent),
	}
	block := types.NewBlock(&header, []*types.Transaction{}, nil, nil, trie.NewStackTrie(nil))

	vmconfig := vm.Config{NoBaseFee: true}
	bc := NewBlockChain(&parent)
	processor := NewStateProcessor(config, bc, bc.Engine())
	_, _, _, err := processor.Process(block, statedb, vmconfig)
	if err == nil {
		t.Fatal()
	}
}

func TestEmptyBatch(t *testing.T) {
	statedb := prepare(t)
	batchTx := makeBatchTx(t, 2, []*types.Transaction{})
	receipts, logs, gasUsed, err := processBatchTx(t, statedb, batchTx)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 0 {
		t.Fatal("expected 0 receipts")
	}
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}
	if gasUsed > 0 {
		t.Fatal("expected 0 gas used")
	}
}

func TestEmptyShutterTx(t *testing.T) {
	statedb := prepare(t)
	unsignedShutterTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            0,
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        big.NewInt(0),
		Gas:              0,
		EncryptedPayload: []byte{},
		BatchIndex:       2,
	}
	shutterTx, err := types.SignNewTx(userKey, signer, unsignedShutterTx)
	if err != nil {
		t.Fatal(err)
	}
	batchTx := makeBatchTx(t, 2, []*types.Transaction{shutterTx})

	receipts, logs, gasUsed, err := processBatchTx(t, statedb, batchTx)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 0 {
		t.Fatal("expected 0 receipts")
	}
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}
	if gasUsed != 0 {
		t.Fatal("expected 0 gas used")
	}
}

func TestEmptyShutterTxWithFee(t *testing.T) {
	statedb := prepare(t)
	unsignedShutterTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            0,
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        big.NewInt(500), // much smaller than base fee
		Gas:              100,
		EncryptedPayload: []byte{},
		BatchIndex:       2,
	}
	shutterTx, err := types.SignNewTx(userKey, signer, unsignedShutterTx)
	if err != nil {
		t.Fatal(err)
	}
	batchTx := makeBatchTx(t, 2, []*types.Transaction{shutterTx})
	userBalancePre := statedb.GetBalance(userAddress)

	receipts, logs, gasUsed, err := processBatchTx(t, statedb, batchTx)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 0 {
		t.Fatal("expected 0 receipts")
	}
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}
	if gasUsed != 0 {
		t.Fatal("expected 0 gas used")
	}

	userBalancePost := statedb.GetBalance(userAddress)
	userBalanceDiff := new(big.Int).Sub(userBalancePost, userBalancePre)

	expectedFee := new(big.Int).Mul(shutterTx.GasFeeCap(), new(big.Int).SetUint64(shutterTx.Gas()))
	if new(big.Int).Neg(userBalanceDiff).Cmp(expectedFee) != 0 {
		t.Fatalf("expected user balance to increase by %d, got %d", expectedFee, new(big.Int).Neg(userBalanceDiff))
	}
}

func TestTransfer(t *testing.T) {
	statedb := prepare(t)

	receiver := common.HexToAddress("2222222222222222222222222222222222222222")
	amount := big.NewInt(100)
	payload := &types.DecryptedPayload{
		To:    &receiver,
		Value: amount,
		Data:  []byte{},
	}
	unsignedShutterTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            statedb.GetNonce(userAddress),
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        big.NewInt(0),
		Gas:              21000,
		EncryptedPayload: encryptPayload(t, payload, 2),
		BatchIndex:       2,
	}
	shutterTx, err := types.SignNewTx(userKey, signer, unsignedShutterTx)
	if err != nil {
		t.Fatal(err)
	}
	batchTx := makeBatchTx(t, 2, []*types.Transaction{shutterTx})

	senderBalancePre := statedb.GetBalance(userAddress)
	receiverBalancePre := statedb.GetBalance(receiver)

	receipts, logs, gasUsed, err := processBatchTx(t, statedb, batchTx)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 {
		t.Fatal("expected 1 receipt")
	}
	if receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatal("tx should have been successful")
	}
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}
	if gasUsed != 21000 {
		t.Fatalf("expected 21000 gas used, got %d", gasUsed)
	}

	senderBalancePost := statedb.GetBalance(userAddress)
	receiverBalancePost := statedb.GetBalance(receiver)

	senderBalanceDiff := new(big.Int).Sub(senderBalancePost, senderBalancePre)
	receiverBalanceDiff := new(big.Int).Sub(receiverBalancePost, receiverBalancePre)

	if senderBalanceDiff.Cmp(new(big.Int).Neg(amount)) != 0 {
		t.Fatalf("expected sender balance to decrease by %d, got increase by %d", amount, senderBalanceDiff)
	}
	if receiverBalanceDiff.Cmp(amount) != 0 {
		t.Fatalf("expected receiver balance to increase by %d, got %d", amount, receiverBalanceDiff)
	}
}

func TestContractCall(t *testing.T) {
	statedb := prepare(t)

	deployPayload := &types.DecryptedPayload{
		To:    nil,
		Value: big.NewInt(0),
		Data:  contractDeployData,
	}
	unsignedDeployTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            statedb.GetNonce(userAddress),
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        big.NewInt(0),
		Gas:              1000000,
		EncryptedPayload: encryptPayload(t, deployPayload, 2),
		BatchIndex:       2,
	}

	contractAddress := common.HexToAddress("0xFA33c8EF8b5c4f3003361c876a298D1DB61ccA4e")
	callPayload := &types.DecryptedPayload{
		To:    &contractAddress,
		Value: big.NewInt(0),
		Data:  contractCallData,
	}
	unsignedCallTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            statedb.GetNonce(userAddress) + 1,
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        big.NewInt(0),
		Gas:              100000,
		EncryptedPayload: encryptPayload(t, callPayload, 2),
		BatchIndex:       2,
	}

	deployTx, err := types.SignNewTx(userKey, signer, unsignedDeployTx)
	if err != nil {
		t.Fatal(err)
	}
	callTx, err := types.SignNewTx(userKey, signer, unsignedCallTx)
	if err != nil {
		t.Fatal(err)
	}
	batchTx := makeBatchTx(t, 2, []*types.Transaction{
		deployTx,
		callTx,
	})

	receipts, logs, _, err := processBatchTx(t, statedb, batchTx)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 2 {
		t.Fatal("expected 2 receipts")
	}
	if receipts[1].Status != types.ReceiptStatusSuccessful {
		t.Fatal("tx should have been successful")
	}
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}
}

func TestContractDeployment(t *testing.T) {
	statedb := prepare(t)

	payload := &types.DecryptedPayload{
		To:    nil,
		Value: big.NewInt(0),
		Data:  contractDeployData,
	}
	unsignedShutterTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            statedb.GetNonce(userAddress),
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        big.NewInt(0),
		Gas:              1000000,
		EncryptedPayload: encryptPayload(t, payload, 2),
		BatchIndex:       2,
	}
	shutterTx, err := types.SignNewTx(userKey, signer, unsignedShutterTx)
	if err != nil {
		t.Fatal(err)
	}
	batchTx := makeBatchTx(t, 2, []*types.Transaction{shutterTx})

	receipts, logs, _, err := processBatchTx(t, statedb, batchTx)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 {
		t.Fatal("expected 1 receipts")
	}
	if receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatal("tx should have been successful")
	}
	if bytes.Equal(receipts[0].ContractAddress.Bytes(), common.Address{}.Bytes()) {
		t.Fatal("should have deployed contract")
	}
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}

	code := statedb.GetCode(receipts[0].ContractAddress)
	if len(code) == 0 {
		t.Fatal("should have deployed contract")
	}
}

func TestGetEonKey(t *testing.T) {
	statedb := prepare(t)

	// mine empty block to test the verification of eon key
	_, _, _, err := processBatchTx(t, statedb, makeBatchTx(t, 2, []*types.Transaction{}))
	if err != nil {
		t.Fatal(err)
	}
}

func TestPlaintextTx(t *testing.T) {
	// Tests that a plaintext tx is properly executed after a ciphertext tx
	statedb := prepare(t)

	receiver := common.HexToAddress("2222222222222222222222222222222222222222")
	amount := big.NewInt(100)
	payload := &types.DecryptedPayload{
		To:    &receiver,
		Value: amount,
		Data:  []byte{},
	}
	unsignedShutterTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            statedb.GetNonce(userAddress),
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        big.NewInt(0),
		Gas:              21000,
		EncryptedPayload: encryptPayload(t, payload, 2),
	}
	shutterTx, err := types.SignNewTx(userKey, signer, unsignedShutterTx)
	if err != nil {
		t.Fatal(err)
	}
	unsignedPlainTx := &types.LegacyTx{
		Nonce:    statedb.GetNonce(userAddress) + 1,
		GasPrice: common.Big0,
		Gas:      21000,
		To:       &receiver,
		Value:    amount,
	}
	plainTx, err := types.SignNewTx(userKey, signer, unsignedPlainTx)
	if err != nil {
		t.Fatal(err)
	}
	batchTx := makeBatchTx(t, 2, []*types.Transaction{shutterTx, plainTx})

	senderBalancePre := statedb.GetBalance(userAddress)
	receiverBalancePre := statedb.GetBalance(receiver)

	receipts, logs, gasUsed, err := processBatchTx(t, statedb, batchTx)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 2 {
		t.Fatal("expected 2 receipt")
	}
	if receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatal("cipher tx should have been successful")
	}
	if receipts[1].Status != types.ReceiptStatusSuccessful {
		t.Fatal("plain tx should have been successful")
	}
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}
	if gasUsed != 42000 {
		t.Fatalf("expected 42000 gas used, got %d", gasUsed)
	}

	senderBalancePost := statedb.GetBalance(userAddress)
	receiverBalancePost := statedb.GetBalance(receiver)

	senderBalanceDiff := new(big.Int).Sub(senderBalancePost, senderBalancePre)
	receiverBalanceDiff := new(big.Int).Sub(receiverBalancePost, receiverBalancePre)
	expectedDiff := new(big.Int).Mul(amount, common.Big2)

	if senderBalanceDiff.Cmp(new(big.Int).Neg(expectedDiff)) != 0 {
		t.Fatalf("expected sender balance to decrease by %d, got increase by %d", expectedDiff, senderBalanceDiff)
	}
	if receiverBalanceDiff.Cmp(expectedDiff) != 0 {
		t.Fatalf("expected receiver balance to increase by %d, got %d", expectedDiff, receiverBalanceDiff)
	}
}
