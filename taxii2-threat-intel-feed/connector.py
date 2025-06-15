"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger('taxii2-threat-intel-feed')


class TAXIIFeedCon(Connector):
    def execute(self, config, operation, params, **kwargs):
        logger.info('In execute() Operation: {}'.format(operation))
        try:
            operation = operations.get(operation)
            # todo let call connector take it from _info
            # now was ingesting it from integration separately
            # changes for fcp/tip specific so it dsnt break on fsr
            if 'connector_name' in kwargs:
                kwargs.pop('connector_name')
            return operation(config, params, **kwargs)
        except Exception as err:
            logger.error('{}'.format(err))
            raise ConnectorError('{}'.format(err))

    def check_health(self, config):
        return _check_health(config)
