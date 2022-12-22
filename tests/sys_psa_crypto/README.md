## Testsuite for PSA Crypto API

This test application builds and runs the PSA Architecture Testsuite (https://github.com/ARM-software/psa-arch-tests).

The cryptographic algorithms to build the PSA Crypto API with can be configured using the app.config file or menuconfig.
The corresponding test cases should be configured by adding them to the testsuite.db file.

The testcases and checkpoints are described in a list in the Arch Test respository: https://github.com/ARM-software/psa-arch-tests/blob/main/api-tests/docs/psa_crypto_testlist.md

### General
| Test Function      | Test Name | Supported |
|--------------------|-----------|-----------|
| PSA Library Init   | test_c001 | y         |

### Generation
| Test Function      | Test Name | Supported |
|--------------------|-----------|-----------|
| Key Generation     | test_c016 | n         |
| Key RNG            | test_c017 | y         |

### Key Management
| Test Function      | Test Name | Supported |
|--------------------|-----------|-----------|
| Import Key         | test_c002 | y         |
| Export Key         | test_c003 | n         |
| Export Public Key  | test_c004 | y         |
| Destroy Key        | test_c005 | y         |
| Attributes         | test_c010 | y         |
| Copy Key           | test_c044 | n         |

### Key Derivation
| Test Function      | Test Name | Supported |
|--------------------|-----------|-----------|
| Setup              | test_c008 | n         |
| Input Bytes        | test_c009 | n         |
| Input Key          | test_c018 | n         |
| Key Agreement      | test_c019 | n         |
| Output Bytes       | test_c020 | n         |
| Output Key         | test_c021 | n         |
| Abort              | test_c022 | n         |
| Capacity           | test_c023 | n         |
| Raw Agreemenet     | test_c043 | n         |

### AEAD
| Test Function      | Test Name | Supported |
|--------------------|-----------|-----------|
| Encrypt            | test_c024 | n         |
| Decrypt            | test_c025 | n         |
| Encrypt Setup      | test_c052 | n         |
| Decrypt Setup      | test_c053 | n         |
| Generate Nonce     | test_c054 | n         |
| Set Nonce          | test_c055 | n         |
| Set Length         | test_c056 | n         |
| Update Ad          | test_c057 | n         |
| Update             | test_c058 | n         |
| Finish             | test_c059 | n         |
| Abort              | test_c060 | n         |
| Verify             | test_c061 | n         |

### Hashes
| Test Function      | Test Name | Supported |
|--------------------|-----------|-----------|
| Compute            | test_c006 | y         |
| Compare            | test_c007 | y         |
| Start              | test_c011 | y         |
| Update             | test_c012 | y         |
| Verify             | test_c013 | y         |
| Finish             | test_c014 | y         |
| Abort              | test_c015 | y         |
| Clone              | test_c045 | n         |
| Suspend            | test_c062 | n         |
| Resume             | test_c063 | n         |

### MAC
| Test Function      | Test Name | Supported |
|--------------------|-----------|-----------|
| Sign Setup         | test_c026 | n         |
| Update             | test_c027 | n         |
| Sign Finish        | test_c028 | n         |
| Verify Setup       | test_c029 | n         |
| Verify Finish      | test_c030 | n         |
| Abort              | test_c031 | n         |
| Compute            | test_c046 | y         |
| Verify             | test_c047 | n         |

### Cipher
| Test Function      | Test Name | Supported |
|--------------------|-----------|-----------|
| Encrypt Setup      | test_c032 | n         |
| Decrypt Setup      | test_c033 | n         |
| Generate IV        | test_c034 | y         |
| Set IV             | test_c035 | n         |
| Update             | test_c036 | n         |
| Finish             | test_c037 | n         |
| Abort              | test_c038 | n         |
| Encrypt            | test_c048 | y         |
| Decrypt            | test_c049 | y         |

### Asymmetric
| Test Function      | Test Name | Supported |
|--------------------|-----------|-----------|
| Encrypt            | test_c039 | n         |
| Decrypt            | test_c040 | n         |
| Sign Hash          | test_c041 | n         |
| Verify Hash        | test_c042 | n         |
