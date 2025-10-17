# Rust Smart Contract Vulnerabilities

A comprehensive guide to common vulnerabilities in Rust-based smart contracts, designed specifically for auditors and security researchers.

## Overview

This repository provides examples, explanations, and detection techniques for various vulnerabilities commonly found in Rust-based smart contracts, particularly those deployed on platforms such as Solana, NEAR, and other blockchains supporting Rust-based contracts.

Each vulnerability is explained with:
- Detailed description and impact
- Vulnerable code examples
- Secure code alternatives
- Detection methodologies
- Real-world examples (where applicable)

## Vulnerabilities Covered

1. **Reentrancy**
   - Cross-program invocation vulnerabilities
   - How they differ from Ethereum's reentrancy issues

2. **Integer Overflow/Underflow**
   - Arithmetic operation safety
   - Rust's handling vs. explicit checks

3. **Unchecked Inputs**
   - Missing validation
   - Deserialization vulnerabilities

4. **Oracle Manipulation**
   - Price oracle vulnerabilities
   - Data feed tampering

5. **Access Control**
   - Privilege escalation
   - Missing authorization checks

6. **Denial of Service**
   - Resource exhaustion
   - Logic-based DoS

7. **Illicit Fee Collection**
   - Fee redirection
   - Hidden fee structures

8. **Flash Loan Attacks**
   - Temporary asset control exploitation
   - Market manipulation

9. **Logic Errors**
   - Incorrect state transitions
   - Business logic flaws

10. **Random Number Manipulation**
    - Predictable randomness
    - Seed manipulation

11. **Signature Verification Bypass**
    - Improper signature validation
    - Replay attack vulnerabilities

12. **Account Confusion**
    - Incorrect account validation
    - Cross-instance attacks on Solana

13. **Front-Running**
    - Transaction ordering exploitation
    - MEV vulnerabilities in Rust contexts

14. **Inadequate Event Emissions**
    - Missing critical events for off-chain monitoring
    - Insufficient logging for security audit trails

15. **Storage/Account Management**
    - Memory safety issues specific to blockchain contexts
    - Account data validation failures

## Usage

The repository is structured to allow easy navigation between vulnerability types. Each vulnerability has:

- Explanatory documentation in markdown
- Code examples showing both vulnerable and secure implementations
- Test cases demonstrating exploitation and mitigation

## Platform-Specific Vulnerabilities

### Solana

- Account validation issues
- Cross-Program Invocation (CPI) security concerns
- PDAs and bump seeds validation
- Instruction data validation
- Compute budget considerations

### NEAR

- Cross-contract call vulnerabilities
- Storage management issues
- Gas efficiency concerns
- Promise chain vulnerabilities

### CosmWasm (Rust on Cosmos)

- Message passing vulnerabilities
- State management issues
- Contract migration risks

### Substrate/Polkadot

- Runtime module interactions
- Governance mechanism vulnerabilities
- Parachain-specific concerns

## Interactive Tools

This repository includes several tools to enhance the learning experience:

1. **Vulnerability Scanner CLI**: A command-line tool that can scan Rust smart contract code for potential security issues.
2. **Exploitation Sandbox**: Interactive examples where you can safely experiment with exploiting vulnerabilities.
3. **Security Checklist Generator**: Creates a tailored security checklist based on your project's characteristics.

## Security Checklists

We provide comprehensive security checklists for auditors reviewing Rust smart contracts:

- **General Rust Smart Contract Checklist**: Universal security considerations for all Rust-based smart contracts
- **Solana-Specific Checklist**: Focusing on Account validation, PDAs, and CPIs
- **NEAR-Specific Checklist**: Addressing cross-contract calls and storage concerns
- **Audit Preparation Checklist**: How to prepare a Rust smart contract codebase for a security audit

## Real-World Case Studies

Learn from historical vulnerabilities discovered in production systems:

- **Case Study 1**: Cross-program invocation vulnerability in a Solana protocol
- **Case Study 2**: Integer overflow exploit in a NEAR application
- **Case Study 3**: Access control bypass in a CosmWasm contract
- **Case Study 4**: Logic error in a high-value DeFi application

## For Auditors

This repository serves as both a reference and a training tool for auditors specializing in Rust-based smart contracts. We recommend:

1. Start by understanding the fundamental differences between Rust smart contracts and those written in other languages like Solidity
2. Review each vulnerability type and understand its specific manifestation in Rust
3. Use the test cases to practice identifying these vulnerabilities
4. Contribute your findings and improvements

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

The code examples in this repository demonstrate vulnerabilities for educational purposes. They should not be used in production environments.


# Vulnerabilities Overview

## /src/vulnerabilities/access_control.rs
**Example 1**   
- **Source:** Line 114 
- **Sink:** Line 122 

**Example 2** 
- **Source:** Line 128  
- **Sink:** Line 146 

**Example 3**  
- **Source:** Line 152
- **Sink:** Line 170 

---

## /src/vulnerabilities/account_confusion.rs
**Example 1**  
- **Source:** Line 133   
- **Sink:** Line 159 

---

## /src/vulnerabilities/denial_of_service.rs
**Example 1**   
- **Source:** Line 111 
- **Sink:** Line 127 

**Example 2** 
- **Source:** Line 111  
- **Sink:** Line 131

**Example 3** 
- **Source/Sink:** Line 149  

---

## /src/vulnerabilities/flash_loan.rs
**Example 1**
- **Source:** Line 181  
- **Sink:** Line 206

**Example 2**
- **Source:** Line 220 
- **Sink:** Line 249

---

## /src/vulnerabilities/front_running.rs
**Example 1**  
- **Source:** Line 138 
- **Sink:** Line 172 

---

## /src/vulnerabilities/illicit_fee_collection.rs
**Example 1**  
- **Source:** Line 133 
- **Sink:** Line 141 

**Example 2**  
- **Source:** Line 147 
- **Sink:** Line 159 

**Example 3**  
- **Source:** Line 165 
- **Sink:** Line 199 

---

## /src/vulnerabilities/inadequate_events.rs
**Example 1**  
- **Source:** Line 124 
- **Sink:** Line 131 

**Example 2**  
- **Source:** Line 149 
- **Sink:** Line 137 

---

## /src/vulnerabilities/logic_errors.rs
**Example 1**  
- **Source:** Line 152 
- **Sink:** Line 166 

**Example 2**  
- **Source:** Line 172 
- **Sink:** Line 198

**Example 3**  
- **Source:** Line 205 
- **Sink:** Line 214

**Example 4**  
- **Source:** Line 205 
- **Sink:** Line 229

**Example 5**  
- **Source:** Line 237 
- **Sink:** Line 243

**Example 6**  
- **Source:** Line 237 
- **Sink:** Line 249

---

## /src/vulnerabilities/oracle_manipulation.rs
**Example 1**  
- **Source:** Line 144
- **Sink:** Line 152

---

## /src/vulnerabilities/overflow.rs
**Example 1**
- **Source:** Line 99 
- **Sink:** Line 104  

**Example 2**  
- **Source:** Line 110
- **Sink:** Line 125  

---

## /src/vulnerabilities/random_manipulation.rs
**Example 1** 
- **Source/Sink:** Line 164  

**Example 2**
- **Source:** Line 177  
- **Sink:** Line 184

**Example 3**
- **Source:** Line 211  
- **Sink:** Line 216

---

## /src/vulnerabilities/reentrancy.rs
**Example 1**  
- **Source:** Line 97 
- **Sink:** Line 112  

---

## /src/vulnerabilities/signature_verification.rs
**Example 1**  
- **Source:** Line 103 
- **Sink:** Line 125

---

## /src/vulnerabilities/storage_management.rs
**Example 1**  
- **Source:** Line 152
- **Sink:** Line 176

**Example 2**  
- **Source/Sink:** Line 152
- **Sink:** Line 196 

---

## /src/vulnerabilities/unchecked_inputs.rs
**Example 1** 
- **Source:** Line 99 
- **Sink:** Line 116

**Example 2** 
- **Source:** Line 129  
- **Sink:** Line 140 

---


