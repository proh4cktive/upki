# -*- coding:utf-8 -*-

import os
import re
import validators

import upkica

class Profiles(upkica.core.Common):
    def __init__(self, logger, storage):
        try:
            super(Profiles, self).__init__(logger)
        except Exception as err:
            raise Exception(err)

        self._storage  = storage
        
        try:
            # Detect all profiles
            self._profiles_list = self._storage.list_profiles()
        except Exception as err:
            raise Exception('Unable to list profiles: {e}'.format(e=err))

    def exists(self, name):
        return bool(name in self._profiles_list.keys())

    def list(self):
        results = dict(self._profiles_list)

        #Avoid disclosing system profiles
        for name in ['admin', 'ca', 'ra']:
            try:
                del results[name]
            except KeyError:
                pass
                
        return results

    def load(self, name):
        if name not in self._profiles_list.keys():
            raise Exception('Profile does not exists')

        try:
            data = self._storage.load_profile(name)
        except Exception as err:
            raise Exception(err)

        try:
            clean = self._check_profile(data)
            self.output('Profile {p} loaded'.format(p=name), level="DEBUG")
        except Exception as err:
            raise Exception(err)

        return clean

    def store(self, name, data):
        """Store a new profile file
        Validate data before pushing to file
        """
        if name in ['ca','ra','admin']:
            raise Exception('Sorry this name is reserved')

        if not (re.match('^[\w\-_\(\)]+$', name) is not None):
            raise Exception('Invalid profile name')

        try:
            clean = self._check_profile(data)
            self.output('New Profile {p} verified'.format(p=name), level="DEBUG")
        except Exception as err:
            raise Exception(err)

        try:
            self._storage.store_profile(name, clean)
        except Exception as err:
            raise Exception(err)

        # Update values if exists
        self._profiles_list[name] = clean

        return clean

    def update(self, original, name, data):
        """Update a profile file
        Validate data before pushing to file
        """
        if name in ['ca','ra','admin']:
            raise Exception('Sorry this name is reserved')

        if not (re.match('^[\w\-_\(\)]+$', name) is not None):
            raise Exception('Invalid profile name')

        if not original in self._profiles_list.keys():
            raise Exception('This profile did not exists')

        if (original != name) and (name in self._profiles_list.keys()):
            raise Exception('Duplicate profile name')

        try:
            clean = self._check_profile(data)
            self.output('Modified profile {o} -> {p} verified'.format(o=original, p=name), level="DEBUG")
        except Exception as err:
            raise Exception(err)

        try:
            self._storage.update_profile(original, name, clean)
        except Exception as err:
            raise Exception(err)

        # Update values if exists
        self._profiles_list[name] = clean

        # Take care of original if neeed
        if original != name:
            try:
                self.delete(original)
            except Exception as err:
                raise Exception(err)

        return clean

    def delete(self, name):
        """Delete profile file, and remove associated key in profiles list
        """
        if name in ['ca','ra','admin']:
            raise Exception('Sorry this name is reserved')

        if not (re.match('^[\w\-_\(\)]+$', name) is not None):
            raise Exception('Invalid profile name')

        try:
            self._storage.delete_profile(name)
        except Exception as err:
            raise Exception(err)

        try:
            # Update values if exists
            del self._profiles_list[name]
        except KeyError as err:
            pass
        
        return True