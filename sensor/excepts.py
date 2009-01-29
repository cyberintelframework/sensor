
import exceptions

changeset = "001"

class ConfigException(exceptions.Exception):
    """ Used for configuration problems """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class InterfaceException(exceptions.Exception):
    """ used for interface problems """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class NetworkException(exceptions.Exception):
    """ used for network problems """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class RunException(exceptions.Exception):
    """ used for when a external program/scripts returns a error code"""
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class DepricatedException(exceptions.Exception):
    """ raised when depricated code is called """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)





