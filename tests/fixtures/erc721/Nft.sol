// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title GalleryNFT - ERC-721 style fixture
contract GalleryNFT {
    string public name = "Gallery";
    string public symbol = "GAL";
    uint256 public nextTokenId = 1;
    address public owner;
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;
    mapping(uint256 => address) public getApproved;
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed spender, uint256 indexed tokenId);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function mint(address to) external onlyOwner returns (uint256 tokenId) {
        tokenId = nextTokenId++;
        ownerOf[tokenId] = to;
        balanceOf[to] += 1;
        emit Transfer(address(0), to, tokenId);
    }

    function approve(address spender, uint256 tokenId) external {
        require(ownerOf[tokenId] == msg.sender, "not owner");
        getApproved[tokenId] = spender;
        emit Approval(msg.sender, spender, tokenId);
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        require(ownerOf[tokenId] == from, "not owner");
        ownerOf[tokenId] = to;
        unchecked {
            balanceOf[from] -= 1;
            balanceOf[to] += 1;
        }
        emit Transfer(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) external {
        this.transferFrom(from, to, tokenId);
    }

    function setApprovalForAll(address, bool) external pure {}
    function isApprovedForAll(address, address) external pure returns (bool) { return false; }
    function supportsInterface(bytes4) external pure returns (bool) { return true; }
    function tokenURI(uint256 tokenId) external pure returns (string memory) {
        require(tokenId > 0, "bad id");
        return "ipfs://example";
    }
}
