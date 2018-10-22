pragma solidity ^0.4.24;

contract Test {
  function one(bytes, bool, uint[]) public pure {}

  function two(uint, uint32[], bytes10, bytes) public pure {}

  function three(address) public pure {}

  function four() public pure returns (address, string) {
    return (0x00a329c0648769A73afAc7F9381E08FB43dBEA72, "test");
  }

  event Transfer(address indexed, address indexed, uint256 indexed);
}
