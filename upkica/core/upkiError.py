# -*- coding: utf-8 -*-

class UPKIError(Exception):
    def __init__(self, code=0, reason=None):
        try:
            self.code = int(code)
        except ValueError:
            raise Exception('Invalid error code')
        
        try:
            self.reason = str(reason)
        except ValueError:
            raise Exception('Invalid reason message')
        
    def __str__(self):
        return repr("Error [{code}]: {reason}".format(code= self.code, reason= self.reason))
