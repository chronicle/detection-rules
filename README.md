# Google Security Operations Detection Rules

This repository contains sample detection rules and dashboards for use within
Google Security Operations.

Rules within the [community](community) directory were created by the Google Security Operations Security team and
members of the Google Security Operations user community. These rules take advantage of the latest
[YARA-L syntax](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax), provide a starter set of rules
that can be used with Google Security Operations' entity graph as well as for other use cases or as inspiration for new use cases.

Rules within the [soc_prime_rules](soc_prime_rules) directory were created by SOC Prime and made available to Google Security Operations
Customers.

Before deploying any rules, using Google Security Operations'
[test rule](https://cloud.google.com/chronicle/docs/detection/manage-all-rules) functionality is considered a best
practice and provides the opportunity for users to tune rules to their environment before creating alerts for them.

Dashboard YAML files can be
[imported](https://cloud.google.com/chronicle/docs/reports/import-export-dashboards#import_dashboards) into Google Security Operations
dashboards using the `Add` - `Import Dashboard` capability found next to the Personal Dashboards or Shared Dashboards
section of the UI. The intent of this is to provide sample dashboards that can serve as templates, inspiration or
starting points for your own dashboards and can be modified as you see fit.

## Getting Started

Rules can be created within your Google Security Operations instance by using the
[Rules Editor](https://cloud.google.com/chronicle/docs/detection/manage-all-rules). Simply download the rule from the
repository and copy the content of the rule to the rule editor when creating a new rule.

To automate rule creation, APIs are available to create/update/delete rules.

Detailed instructions can be found in your Google Security Operations instance under documentation.

## How to Contribute

Interested in contributing to this project? We'd love to hear from you! Example contributions include new detection
rules and updates to existing rules.

Please refer to our [contribution guide](CONTRIBUTING.md) for further information.

Our style guide for authoring YARA-L detection rules can be found [here](STYLE_GUIDE.md).

## Documentation

### Detection API and UI

* https://cloud.google.com/chronicle/docs/reference/detection-engine-api
* https://cloud.google.com/chronicle/docs/how-to#monitoring-events-using-rules

### YARA-L 2.0 rules and UDM:

* https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview
* https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax
* https://cloud.google.com/chronicle/docs/unified-data-model/udm-usage
* https://cloud.google.com/chronicle/docs/reference/udm-field-list

### Code Samples

* https://github.com/chronicle/api-samples-python/tree/master/detect/v2
