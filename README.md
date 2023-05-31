# Chronicle Detection Rules

This repository contains sample detection rules for use within Chronicle.

Rules within the [soc_prime_rules](soc_prime_rules) directory were created by
SOC Prime and made available to Chronicle Customers.

Rules within the [community](community) directory were created by the Security Adoption engineering team. These rules take advantage of the latest YARA-L syntax, provide a starter set of rules that can be used with Chronicle's entity graph as well as for other use cases or as inspiration for new use cases.

## Getting Started

Rules can be created within your Chronicle instance by using the Rules Editor.
Simply download the rule from the repository and copy the content of the rule to
the rule editor when creating a new rule.

To automate rule creation, APIs are available to create/update/delete rules.

Detailed instructions can be found in your Chronicle instance under
documentation:

## Documentation

Detection API and UI:

*   https://cloud.google.com/chronicle/docs/reference/detection-engine-api
*   https://cloud.google.com/chronicle/docs/how-to#monitoring-events-using-rules

YARA-L 2.0 rules and UDM:

*   https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview
*   https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax
*   https://cloud.google.com/chronicle/docs/unified-data-model/udm-usage
*   https://cloud.google.com/chronicle/docs/reference/udm-field-list

## Code Samples

https://github.com/chronicle/api-samples-python/tree/master/detect/v2
