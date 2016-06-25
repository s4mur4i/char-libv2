from misc.Logger import logger


def validate_kerrigan_json(stack_data, env):
    # do some tests
    logger.debug(msg="Validating if stack can be deployed to env")
    if 'envs' in stack_data and env in stack_data['envs']:
        logger.info(msg="Stack can be deployed to environment %s" % (env,))
    else:
        logger.error(msg="Stack should not be deployed to Environment %s" % (env,))
        exit(20)
    return stack_data
