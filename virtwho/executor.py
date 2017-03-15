import time
from threading import Event
from Queue import Empty, Queue
import errno
import socket
import sys

from virtwho import log, MinimumSendInterval

from virtwho.config import ConfigManager
from virtwho.datastore import Datastore
from virtwho.manager import (
    Manager, ManagerThrottleError, ManagerError, ManagerFatalError)
from virtwho.virt import (
    AbstractVirtReport, ErrorReport, DomainListReport,
    HostGuestAssociationReport, Virt, DestinationThread)

try:
    from collections import OrderedDict
except ImportError:
    # Python 2.6 doesn't have OrderedDict, we need to have our own
    from util import OrderedDict


class ReloadRequest(Exception):
    ''' Reload of virt-who was requested by sending SIGHUP signal. '''


class Executor(object):
    def __init__(self, logger, options, config_dir=None):
        """
        Executor class provides bridge between virtualization supervisor and
        Subscription Manager.

        logger - logger instance
        options - options for virt-who, parsed from command line arguments
        """
        self.logger = logger
        self.options = options
        self.terminate_event = Event()
        self.virts = []
        self.destinations = []

        # Queue for getting events from virt backends
        self.datastore = Datastore()
        self.reloading = False

        self.configManager = ConfigManager(self.logger, config_dir)

        for config in self.configManager.configs:
            logger.debug("Using config named '%s'" % config.name)

    def run(self):
        self.reloading = False
        if not self.options.oneshot:
            self.logger.debug("Starting infinite loop with %d seconds interval", self.options.interval)

        # Queue for getting events from virt backends
        if self.datastore is None:
            self.datastore = Datastore()

        # Run the virtualization backends and destinations
        self.virts = []
        self.destinations = []
        # Need to update the dest to source mapping of the configManager object
        # here because of the way that main reads the config from the command
        # line
        self.configManager.update_dest_to_source_map()

        for config in self.configManager.configs:
            try:
                logger = log.getLogger(config=config)
                virt = Virt.from_config(logger, config, self.datastore,
                                        terminate_event=self.terminate_event,
                                        interval=self.options.interval,
                                        oneshot=self.options.oneshot)
            except Exception as e:
                self.logger.error('Unable to use configuration "%s": %s', config.name, str(e))
                continue
            # Run the thread
            virt.start()
            self.virts.append(virt)

        for info in self.configManager.dests:
            source_keys = self.configManager.dest_to_sources_map[info]
            info.name = "Destination_%s" % hash(info)
            logger = log.getLogger(name=info.name)
            manager = Manager.fromInfo(logger, self.options, info)
            dest = DestinationThread(config=info, logger=logger,
                                     source_keys=source_keys,
                                     options=self.options,
                                     source=self.datastore, dest=manager,
                                     terminate_event=self.terminate_event,
                                     interval=self.options.interval,
                                     oneshot=self.options.oneshot)
            dest.start()
            self.destinations.append(dest)

        if len(self.virts) == 0:
            err = "virt-who can't be started: no suitable virt backend found"
            self.logger.error(err)
            self.stop_threads()
            sys.exit(err)

        # Need to find sources that have no destination to go to

        if len(self.destinations) <= 0:
            # Try to use the default destination (the one that the local system
            # is currently registered to.)
            self.logger.warning("No destinations found, using default")
            try:
                # Find sources that have no destination to go to
                source_keys = list(self.configManager.sources)
                logger = log.getLogger(name="Default_Destination")
                manager = Manager.fromOptions(logger, self.options)
                # Set the name of the given options to
                self.options.name = "Destination_Default"
                dest = DestinationThread(config=self.options, logger=logger,
                                         source_keys=source_keys,
                                         options=self.options,
                                         source=self.datastore, dest=manager,
                                         terminate_event=self.terminate_event,
                                         interval=self.options.interval,
                                         oneshot=self.options.oneshot)
                dest.start()
                self.destinations.append(dest)
            except:
                err = "virt-who can't be started: no suitable destination found"
                self.logger.exception(err)
                self.stop_threads()
                sys.exit(err)

        # Interruptibly wait on the other threads to be terminated
        while not self.terminated():
            time.sleep(1)

        self.stop_threads()

        # TODO: Completely rewrite how the --print option is handled
        if self.options.print_:
            return self.to_print

    def terminated(self):
        """
        @return: Returns whether or not we have terminated
        @rtype: bool
        """
        result = True
        if self.destinations and self.virts:
            all_dests_terminated = all([thread.is_terminated() for thread in
                         self.destinations])
            all_virts_terminated = all([thread.is_terminated() for thread in
                                self.virts])
            result = all_dests_terminated and all_virts_terminated
        return result

    def stop_threads(self):
        print "STOPPING THREADS"
        if self.terminate_event.is_set():
            return
        self.terminate_event.set()
        for thread in self.virts:
            thread.stop()
            thread.join()
        self.virts = []
        # Handle using the --print option
        self.to_print = []
        for thread in self.destinations:
            thread.stop()
            thread.join()
            self.to_print.extend(thread.reports_to_print)
        self.destinations = []
        print "THREADS SHOULD BE STOPPED"

    def terminate(self):
        self.logger.debug("virt-who is shutting down")
        self.stop_threads()

    def reload(self):
        self.logger.warn("virt-who reload")
        # Set the terminate event in all the virts
        self.stop_threads()
        self.reloading = True
