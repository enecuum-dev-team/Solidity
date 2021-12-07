pragma solidity ^0.8.0;

interface IERC20 {

    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);

    function transfer(address recipient, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);


    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

contract ECDSA {

    function lite_verify_array(address token, bytes32 hash, address[] memory owner, uint8[] memory v, bytes32[] memory r, bytes32[] memory s) public returns (bool) {
        //sig array 
        //1 - owner
        //2 - r
        //3 - s
        //4 - v
        require(owner.length > 0, "Empty owner array");
        bool result = true;
        for (uint i=0; i<owner.length; i++){
           // bytes32 
            if(owner[i] != ecrecover(hash, v[i], r[i], s[i])){
                result = false;
                break;
            }
        }
        if(result){
            result = IERC20(token).transferFrom(msg.sender, address(this), 1);
            require(result, "Token transfer failed");
        }
        return result;
    }

    /**
    * @dev prefix a bytes32 value with "\x19Ethereum Signed Message:" and hash the result
    */
    function ethMessageHash(bytes32 message) private pure returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32"  , message)
        );
    }
 
    function ethInvoceHash(address token, address _addr, uint amount) public pure returns (bytes32)  {
        return keccak256(abi.encodePacked(token, _addr,  amount));
    }
}