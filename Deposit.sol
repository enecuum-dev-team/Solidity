// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import  "./ECDSA.sol";

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


interface CERC20 {
    function mint(uint256) external returns (uint256);

    function exchangeRateCurrent() external returns (uint256);

    function supplyRatePerBlock() external returns (uint256);

    function redeem(uint) external returns (uint);

    function redeemUnderlying(uint) external returns (uint);
}

interface COMPTROLLER {
    function claimComp(address holder, CERC20[] memory cTokens) external view returns (uint256);
    function claimComp(address holder) external view returns (uint256);
}

contract Deposit {
    
    ECDSA interfaceECDSA;

    event MyLog(string, uint256);

    mapping(address => mapping (address => uint256)) public balances;

    mapping(address => mapping (address => uint256)) public c_balances;

    mapping(address => mapping (address => uint256))  allowed;
    
    mapping(bytes32 => bool) public invoices;

    
    using SafeMath for uint256;
    
    constructor() {
        interfaceECDSA = new ECDSA();
    }


    function lock(address token, uint256 amount, string memory enq_address) public {
        require(
            amount <= IERC20(token).balanceOf(msg.sender), 
            "Token balance is too low"
        );
        require(
            IERC20(token).allowance(msg.sender, address(this)) >= amount,
            "Token allowance too low"
        );
        require(
            bytes(enq_address).length == 66,
            "Invalid ENQ address format"
        );
        balances[msg.sender][token] = balances[msg.sender][token].add(amount);
        bool sent = IERC20(token).transferFrom(msg.sender, address(this), amount);
        require(sent, "Token transfer failed");
    }
    
    function lock_with_deposit(address token, address c_token, uint256 amount) public {
        require(
            amount <= IERC20(token).balanceOf(msg.sender), 
            "Token balance is too low"
        );
        require(
            IERC20(token).allowance(msg.sender, address(this)) >= amount,
            "Token allowance too low"
        );
        balances[msg.sender][token] = balances[msg.sender][token].add(amount);
        bool sent = IERC20(token).transferFrom(msg.sender, address(this), amount);
        require(sent, "Token transfer failed");
        supplyErc20ToCompound(token, c_token, amount);
    }
    
    function unlock(address token, address recipient, uint256 amount, bytes memory sign) public {
        bytes32 invoice_hash = interfaceECDSA.ethInvoceHash(token, recipient, amount);
        bool exits = invoices[invoice_hash];
        require(!exits, "Invoice has already been used.");
        bool valid_sign = interfaceECDSA.verify(token, recipient, amount, sign);
        require(valid_sign, "Invalid signature. Unlock failed");
        
        bool sent = IERC20(token).transfer(recipient, amount);
        require(sent, "Token transfer failed");
        invoices[invoice_hash] = true;
    }

    function supplyErc20ToCompound(
        address token,
        address c_token,
        uint256 amount
    ) private returns (uint) {
        // Create a reference to the underlying asset contract, like DAI.
        IERC20 underlying = IERC20(token);

        // Create a reference to the corresponding cToken contract, like cDAI
        CERC20 cToken = CERC20(c_token);

        // Amount of current exchange rate from cToken to underlying
        uint256 exchangeRateMantissa = cToken.exchangeRateCurrent();
        emit MyLog("Exchange Rate (scaled up): ", exchangeRateMantissa);

        // Amount added to you supply balance this block
        uint256 supplyRateMantissa = cToken.supplyRatePerBlock();
        emit MyLog("Supply Rate: (scaled up)", supplyRateMantissa);

        // Approve transfer on the ERC20 contract
        underlying.approve(c_token, amount);

        // Mint cTokens
        uint mintResult = cToken.mint(amount);
        
        balances[msg.sender][token] = balances[msg.sender][token].sub(amount);
        c_balances[msg.sender][c_token] = c_balances[msg.sender][c_token].add(amount);

        return mintResult;
    }
    
    function claimComp(address comtroller, address holder) public {
        COMPTROLLER troller = COMPTROLLER(comtroller);
        troller.claimComp(holder);
    }
}

library SafeMath {
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
      assert(b <= a);
      return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
      uint256 c = a + b;
      assert(c >= a);
      return c;
    }
}
