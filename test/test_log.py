import logging

def _setup_logging():

    _default_log_handler = logging.StreamHandler()
    formatter = logging.Formatter(logging.BASIC_FORMAT)
    _default_log_handler.setFormatter(formatter)
    logging.getLogger().addHandler(_default_log_handler)
    logging.getLogger().setLevel(logging.INFO)


#     logging.config.fileConfig(_options.log_config)

def _pre_startup(verbose=None):

    _setup_logging()  
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        
