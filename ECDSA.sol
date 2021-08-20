pragma solidity ^0.8.0;



contract ECDSA {

    function verify(address token, address eth_address, uint amount, bytes memory  sig) public pure returns (bool) {
        bytes32 invoice = ethInvoceHash(token, eth_address, amount);
        bytes32 data_hash = ethMessageHash(invoice);
        //bytes memory sig = hex"bceab59162da5e511fb9c37fda207d443d05e438e5c843c57b2d5628580ce9216ffa0335834d8bb63d86fb42a8dd4d18f41bc3a301546e2c47aa1041c3a1823701";
        //sig = hex"25203287171f44954874c80a156ce20594c4835d972780d053ab8795834d3eb551da0dd98781be60d51515bbfac223e0a8ac71ffc713804c21d6306cc066a97f1b";
        address addr = 0x1F04445E17AA4B64cc9390fd2f76474A5e9B72c1;

        return recover(data_hash, sig) == addr;
    }


    
    /**
     * @dev Recover signer address from a message by using their signature
     * @param hash bytes32 message, the hash is the signed message. What is recovered is the signer address.
     * @param sig bytes signature, the signature is generated using web3.eth.sign()
     */
    function recover(bytes32 hash, bytes memory sig) private pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        // Check the signature length
        if (sig.length != 65) {
            return (address(0));
        }

        // Divide the signature in r, s and v variables
        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
        if (v < 27) {
            v += 27;
        }

        // If the version is correct return the signer address
        if (v != 27 && v != 28) {
            return (address(0));
        } else {
            // solium-disable-next-line arg-overflow
            return ecrecover(hash, v, r, s);
        }
    }

    /**
    * @dev prefix a bytes32 value with "\x19Ethereum Signed Message:" and hash the result
    */
    function ethMessageHash(bytes32 message) private pure returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32"  , message)
        );
    }
 
    function ethInvoceHash(address token, address _addr, uint amount) public pure  returns (bytes32)  {
        return keccak256(abi.encodePacked(token, _addr,  amount));
    }
}