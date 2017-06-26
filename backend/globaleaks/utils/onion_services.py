# -*- coding: utf-8 -*-
# pylint: disable=no-member,import-error
from distutils.version import StrictVersion as V

import txtorcon
from txtorcon import build_local_tor_connection
from twisted.internet import reactor
from twisted.internet.error import ConnectionRefusedError
from twisted.internet.defer import inlineCallbacks, Deferred

from globaleaks.orm import transact_sync
from globaleaks.models.config import PrivateFactory
from globaleaks.utils.utility import log

# Only use mock if txtorcon does not support ephemeral services.
if V(txtorcon.__version__) < V('0.15.1'):
   from globaleaks.mocks.txtorcon_mocks import EphemeralHiddenService
else:
   from txtorcon.torconfig import EphemeralHiddenService


@transact_sync
def db_store_onion_service(store, priv_key, hostname):
    priv_fact = PrivateFactory(store)
    priv_fact.set_val('tor_onion_priv_key', priv_key)
    priv_fact.set_val('tor_onion_hostname', hostname)


@inlineCallbacks
def db_configure_tor_hs(store, bind_port):
    priv_key = PrivateFactory(store).get_val('tor_onion_priv_key')

    log.info('Starting up Tor connection')
    try:
        tor_conn = yield build_local_tor_connection(reactor)
        tor_conn.protocol.on_disconnect = Deferred()
    except ConnectionRefusedError as e:
        log.err('Tor daemon is down or misconfigured . . . starting up anyway')
        return
    log.debug('Successfully connected to Tor control port')

    hs_loc = ('80 localhost:%d' % bind_port)
    if priv_key == '':
        log.info('Creating new onion service')
        ephs = EphemeralHiddenService(hs_loc)
        yield ephs.add_to_tor(tor_conn.protocol)
        log.info('Received hidden service descriptor')
        db_store_onion_service(ephs.private_key, ephs.hostname)
    else:
        log.info('Setting up existing onion service')
        ephs = EphemeralHiddenService(hs_loc, priv_key)
        yield ephs.add_to_tor(tor_conn.protocol)

    @inlineCallbacks
    def shutdown_hs():
        # TODO(nskelsey) move out of configure_tor_hs. Closure is used here for
        # ephs.hostname and tor_conn which must be reused to shutdown the onion
        # service. In later versions of Tor 2.7 > it is possible to detach the
        # the hidden service and thus start a new control conntection to bring
        # ensure that the hidden service is closed cleanly.
        log.info('Shutting down Tor onion service %s' % ephs.hostname)
        if not getattr(tor_conn.protocol.on_disconnect, 'called', True):
            log.debug('Removing onion service')
            yield ephs.remove_from_tor(tor_conn.protocol)
        log.debug('Successfully handled Tor cleanup')

    reactor.addSystemEventTrigger('before', 'shutdown', shutdown_hs)
    log.info('Succeeded configuring Tor to server %s' % (ephs.hostname))


@transact_sync
def configure_tor_hs(store, bind_port):
    return db_configure_tor_hs(store, bind_port)