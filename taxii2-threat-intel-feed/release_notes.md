#### The following enhancements have been made to the TAXII Threat Intel Feed Connector in version 1.2.1:

- The connector has been renamed to `TAXII Threat Intel Feed` from `TAXII2 Threat Intel Feed`.
- Added a new action and a corresponding playbook - `Get Objects`.
- Renamed the configuration parameter `Server URL` to `Server URL (API Root)`.
- Under the action `Fetch Indicators`, renamed the parameter `Created After` to `Added After`.
- Corrected field mapping for following fields during data ingestion:
    - Pattern Type
    - Pattern Version
    - Source
    - Kill Chain Phases
- Updated the connector to support `TAXII v2.1` and `STIX v2.1` protocols.