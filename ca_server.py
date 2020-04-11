#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import sys
import os
import re
import argparse
import logging

import upkica

def main(argv):
    BASE_DIR    = os.path.join(os.path.expanduser("~"), '.upki', 'ca/')
    LOG_FILE    = "ca.log"
    LOG_PATH    = os.path.join(BASE_DIR, LOG_FILE)
    LOG_LEVEL   = logging.INFO
    VERBOSE     = True
    LISTEN_HOST = '127.0.0.1'
    LISTEN_PORT = 5000
    CA_PATH     = None

    parser = argparse.ArgumentParser(description="µPki [maɪkroʊ ˈpiː-ˈkeɪ-ˈaɪ] is a small PKI in python that should let you make basic tasks without effort.")
    parser.add_argument("-q", "--quiet", help="Output less infos", action="store_true")
    parser.add_argument("-d", "--debug", help="Output debug mode", action="store_true")
    parser.add_argument("-l", "--log", help="Define log file (default: {f})".format(f=LOG_PATH), default=LOG_PATH)
    parser.add_argument("-p", "--path", help="Define uPKI directory base path for config and logs (default: {p})".format(p=BASE_DIR), default=BASE_DIR)

    # Allow subparsers
    subparsers = parser.add_subparsers(title='commands')
    
    parser_init = subparsers.add_parser('init', help="Initialize your PKI.")
    parser_init.set_defaults(which='init')
    parser_init.add_argument("-c", "--ca", help="Import CA keychain rather than generating. A path containing 'ca.key, ca.csr, ca.crt' all in PEM format must be defined.")

    parser_register = subparsers.add_parser('register', help="Enable the 0MQ server in clear-mode. This allow to setup your RA certificates.")
    parser_register.set_defaults(which='register')
    parser_register.add_argument("-i", "--ip", help="Define listening IP", default=LISTEN_HOST)
    parser_register.add_argument("-p", "--port", help="Define listening port", default=LISTEN_PORT)

    parser_listen = subparsers.add_parser('listen', help="Enable the 0MQ server in TLS. This enable interactions by events emitted from RA.")
    parser_listen.set_defaults(which='listen')
    parser_listen.add_argument("-i", "--ip", help="Define listening IP", default=LISTEN_HOST)
    parser_listen.add_argument("-p", "--port", help="Define listening port", default=LISTEN_PORT)
    
    args = parser.parse_args()

    try:
        # User MUST call upki with a command
        args.which
    except AttributeError:
        parser.print_help()
        sys.exit(1)

    # Parse common options
    if args.quiet:
        VERBOSE = False
    
    if args.debug:
        LOG_LEVEL = logging.DEBUG

    if args.path:
        BASE_DIR = args.path

    if args.log:
        LOG_PATH = args.log

    LOG_PATH    = os.path.join(BASE_DIR, 'logs/', LOG_FILE)

    # Generate logger object
    try:
        logger = upkica.core.PHKLogger(LOG_PATH, level=LOG_LEVEL, proc_name="upki_ca", verbose=VERBOSE)
    except Exception as err:
        raise Exception('Unable to setup logger: {e}'.format(e=err))

    # Meta information
    dirname = os.path.dirname(__file__)

    # Retrieve all metadata from project
    with open(os.path.join(dirname, '__metadata.py'), 'rt') as meta_file:
        metadata = dict(re.findall(r"^__([a-z]+)__ = ['\"]([^'\"]*)['\"]", meta_file.read(), re.M))

    logger.info("\t\t..:: µPKI - Micro PKI ::..", color="WHITE", light=True)
    logger.info("version: {v}".format(v=metadata['version']), color="WHITE")

    # Setup options
    CA_OPTIONS = upkica.utils.Config(logger, BASE_DIR, LISTEN_HOST, LISTEN_PORT)

    try:
        # Init PKI
        pki = upkica.ca.Authority(CA_OPTIONS)
    except Exception as err:
        logger.critical(err)
        sys.exit(1)

    # Initialization happens while there is nothing on disk yet
    if args.which is 'init':
        if args.ca:
            CA_PATH = args.ca
        try:
            pki.initialize(keychain=CA_PATH)
        except Exception as err:
            logger.critical('Unable to initialize the PKI')
            logger.critical(err)
            sys.exit(1)
        
        # Build compliant register command
        cmd = "$ {p}".format(p=sys.argv[0])
        if BASE_DIR != os.path.join(os.path.expanduser("~"), '.upki/'):
            cmd += " --path {d}".format(d=BASE_DIR)
        cmd += " register"
        if LISTEN_HOST != '127.0.0.1':
            cmd += " --ip {h}".format(h=LISTEN_HOST)
        if LISTEN_PORT != 5000:
            cmd += " --port {p}".format(p=LISTEN_PORT)
        
        logger.info("Congratulations, your PKI is now initialized!", light=True)
        logger.info("Launch your PKI with 'register' argument...", light=True)
        logger.info(cmd, light=True)
        sys.exit(0)
    else:
        if args.ip:
            LISTEN_HOST = args.ip
        if args.port:
            LISTEN_PORT = args.port

    try:
        pki.load()
    except Exception as err:
        logger.critical('Unable to load the PKI')
        logger.critical(err)
        sys.exit(1)

    
    if args.which is 'register':
        try:
            pki.register(LISTEN_HOST, LISTEN_PORT)
        except SystemExit:
            sys.exit(1)
        except Exception as err:
            logger.critical('Unable to register the PKI RA')
            logger.critical(err)
            sys.exit(1)
        
        logger.info("Congratulations, your RA is now registrated!", light=True)
        logger.info("Launch your CA with 'listen' argument", light=True)
        sys.exit(0)

    try:
        pki.listen(LISTEN_HOST, LISTEN_PORT)
    except Exception as err:
        logger.critical('Unable to start listen process')
        logger.critical(err)
        sys.exit(1)

if __name__ == '__main__':
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        sys.stdout.write('\nBye.\n')