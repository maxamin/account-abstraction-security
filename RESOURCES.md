# Resources

## Standards
- [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337), [ERC-7562](https://eips.ethereum.org/EIPS/eip-7562)
- [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702), [ERC-7201](https://eips.ethereum.org/EIPS/eip-7201)
- [ERC-7579](https://eips.ethereum.org/EIPS/eip-7579), [ERC-6900](https://eips.ethereum.org/EIPS/eip-6900), [ERC-7484](https://eips.ethereum.org/EIPS/eip-7484)
- [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712) (typed data signing), [EIP-2612](https://eips.ethereum.org/EIPS/eip-2612) (permit)

## Implementations
- [eth-infinitism/account-abstraction](https://github.com/eth-infinitism/account-abstraction) (EntryPoint, `BaseAccount`, sample paymasters)
- [Safe](https://github.com/safe-global/safe-smart-account), [Kernel](https://github.com/zerodevapp/kernel)
- [ERC-4337 docs](https://docs.erc4337.io)

## Bundlers
- [eth-infinitism bundler](https://github.com/eth-infinitism/bundler) (reference, TypeScript)
- [Rundler](https://github.com/alchemyplatform/rundler) (Alchemy, Rust)
- [Alto](https://github.com/pimlicolabs/alto) (Pimlico, TypeScript)

## Tooling
- [Foundry](https://book.getfoundry.sh) (7702 cheatcodes, invariant testing, `cast send --auth`)
- [Rhinestone ModuleKit](https://github.com/rhinestonewtf/modulekit) (ERC-7579 module development and testing)
- [Slither](https://github.com/crytic/slither) (function summaries, entry-point mapping)
- [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) (`ECDSA.tryRecover`, ERC-1271 helpers)

## Related books in this wiki
- **oracle-security-engineering** (ERC-20 paymaster pricing)
- **ai-agent-wallet-security** (session keys for agents)
- **ai-assisted-audit-playbook** (verification-first AI audit workflow)
