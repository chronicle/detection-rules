# Google Security Operations Detection Rules

This repository contains example YARA-L rules and dashboards for use within
[Google Security Operations (SecOps)](https://cloud.google.com/security/products/security-operations).

The rules in this repository are distinct from Google SecOps
[Curated Detections](https://cloud.google.com/chronicle/docs/detection/curated-detections)
that are developed by Google Cloud Threat Intelligence and designed to generate
detections & alerts that are highly actionable. Curated Detections are available
to Google SecOps customers with an Enterprise license or higher.

Before deploying any rules, using Google SecOps' [test rule](https://cloud.google.com/chronicle/docs/detection/manage-all-rules)
functionality is considered a best practice and provides the opportunity for
users to tune rules to their environment before creating alerts for them.

Dashboard YAML files can be [imported](https://cloud.google.com/chronicle/docs/reports/import-export-dashboards#import_dashboards)
into Google SecOps dashboards using the `Add` - `Import Dashboard` capability
found next to the Personal Dashboards or Shared Dashboards section of the UI.
The intent of this is to provide sample dashboards that can serve as templates,
inspiration or starting points for your own dashboards and can be modified as
you see fit.

## Directory Structure

| Directory                                    | Description                    |
|--------------------------------------------- | ------------------------------ |
| [`rules/community/`](rules/community/)       | YARA-L rules created by members of the Google SecOps team and user community |
| [`tools/content_manager/`](tools/content_manager/) | CLI tool used to manage rules and other content via Google SecOps' REST API |

## Getting Started

Rules can be created within your Google SecOps instance by using the
[Rules Editor](https://cloud.google.com/chronicle/docs/detection/manage-all-rules).
Simply download the rule from the repository and copy the content of the rule
to the rules editor when creating a new rule.

Detailed instructions can be found in your Google SecOps instance under
documentation.

The [rule manager](tools/rule_manager/) tool and accompanying documentation &
tutorials can be used to easily implement a Detection-as-Code pipeline for
managing rules via Google SecOps' [REST API](https://cloud.google.com/chronicle/docs/reference/rest).

## How to Get Help

If you have questions related to this project, please open a new issue in this
GitHub repository. You can also ask questions related to Google SecOps in the
[Google Cloud Security Community](https://secopscommunity.com).

## How to Contribute

Interested in contributing to this project? We'd love to hear from you! Example
contributions include new rules and updates to existing rules.

Please refer to our [contribution guide](CONTRIBUTING.md) for further
information.

Our style guide for authoring YARA-L detection rules can be found [here](STYLE_GUIDE.md).

## Useful Resources

### YARA-L rules and Unified Data Model (UDM)

* [Monitoring events using rules](https://cloud.google.com/chronicle/docs/how-to#monitoring-events-using-rules)
* [Overview of the YARA-L language](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview)
* [YARA-L language syntax](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax)
* [Unified Data Model usage guide](https://cloud.google.com/chronicle/docs/unified-data-model/udm-usage)
* [Unified Data Model field list](https://cloud.google.com/chronicle/docs/reference/udm-field-list)

### Code Samples

* [Example Code for interacting with Google SecOps' API](https://github.com/chronicle/api-samples-python/tree/master/detect/v1alpha)
