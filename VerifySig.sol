// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.3;

contract VerifySignature {

    event hashMatched (bytes32 message);
   
    function getMessageHash() public view returns (bytes32) {

        return keccak256(abi.encodePacked(msg.sender, address(this)));

    }

    function getMetamaskSignedMessage(bytes32 _messageHash) public returns (bytes32)
    {     
        
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));     
    
    }

    function verify( bytes memory signature) public returns (bool) {

        bytes32 messageHash = getMessageHash();

        bytes32 metamaskSignedMessage = getMetamaskSignedMessage(messageHash);


        if (recoverSigner(metamaskSignedMessage, signature) == msg.sender) 

       { 
           emit hashMatched (metamaskSignedMessage);
           return true;
       }
 

    }

    function recoverSigner(bytes32 _getMetamaskSignedMessage, bytes memory _signature) public returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_getMetamaskSignedMessage, v, r, s);
    }

    function splitSignature(bytes memory sig) public returns (
            bytes32 r,
            bytes32 s,
            uint8 v
        )
    {
        require(sig.length == 65, "signature length should be = 65");

        assembly {
        
            r := mload(add(sig, 32))
       
            s := mload(add(sig, 64))
       
            v := byte(0, mload(add(sig, 96)))
        }

    }
}


contract VerifySignatureChild is VerifySignature {}
