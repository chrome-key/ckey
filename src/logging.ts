import logger from 'loglevel';
import prefix from 'loglevel-plugin-prefix';

prefix.reg(logger);

export const getLogger = (loggerName: string): logger.Logger => {
    const log = logger.getLogger(loggerName);
    log.setLevel(logger.levels.DEBUG);
    prefix.apply(log, {
        template: '%t [%n] - %l',
        timestampFormatter: (date) => date.toLocaleString(),
    });
    return log;
};
