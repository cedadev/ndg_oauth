class RenderingConfiguration(object):
    """Holds configuration parameters for renderer.
    """
    __slots__ = ('__params')

    def __init__(self, pamameterNames, prefix, kw):
        """
        @type parameterNames: iterable
        @param parameterNames: names for which parameters are to be initialised
        @type prefix: basestring
        @param prefix: prefix matching start of relevant 
        @type kw: dict
        @param kw: key/value pairs of parameter names including the prefix and
        corresponding values
        """
        self.__params = dict.fromkeys(pamameterNames, '')
        prefixLength = len(prefix)
        for k, v in kw.iteritems():
            if k.startswith(prefix):
                self.__params[k[prefixLength:]] = v

    @property
    def parameters(self):
        return self.__params

    def merged_parameters(self, parameters):
        """Returns a copy of the parameters merged with specified additional
        ones.
        @type parameters: dict
        @param parameters: parameter name/value pairs to merge
        @rtype: dict
        @return: merged parameters
        """
        result = self.__params.copy()
        for k, v in parameters.iteritems():
            result[k] = v
        return result
