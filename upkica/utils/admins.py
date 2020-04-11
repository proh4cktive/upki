# -*- coding:utf-8 -*-

import upkica

class Admins(upkica.core.Common):
    def __init__(self, logger, storage):
        try:
            super(Admins, self).__init__(logger)
        except Exception as err:
            raise Exception(err)

        self._storage  = storage
        
        self.list()

    def exists(self, dn):
        for i, adm in enumerate(self._admins_list):
            if adm['dn'] == dn:
                return True
        return False

    def list(self):
        try:
            # Detect all admins
            self._admins_list = self._storage.list_admins()
        except Exception as err:
            raise Exception('Unable to list admins: {e}'.format(e=err))
        return self._admins_list

    def store(self, dn):
        if self.exists(dn):
            raise Exception('Already admin.')
        try:
            self._storage.add_admin(dn)
        except Exception as err:
            raise Exception(err)

        return dn

    def delete(self, dn):
        try:
            self._storage.delete_admin(dn)
        except Exception as err:
            raise Exception(err)

        return dn