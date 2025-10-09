# x509-Anvil

After undergoing a major re-write. X.509-Anvil is now functioning as intended again.

The old code written by Jonas Thiele in their Master's thesis is saved in the `legacy` branch.

## Profiles

There are two main default profiles. The `rfc5280` profile tests all test cases that are included in the RFC directly.
The `bsi` profile runs all tests that are included in the RFC with additional requirements from the BSI.

## Metadata Remark

Note that we omit the reference to the BSI section if there is a reference to the RFC already. In large parts, the BSI section just references the RFC itself.
