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

    def _create_virt_backends(self, reset=False):
        """Populate self.virts with virt backend threads

            @param reset: Whether to kill existing backends or not, defaults
            to false
            @type: bool
        """
        if reset and self.virts is not None and len(self.virts) > 0:
            self.terminate_threads(self.virts)

        self.virts = []

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
            self.virts.append(virt)

    def _create_destinations(self, reset=False):
        """Populate self.destinations with a list of  list with them

            @param reset: Whether to kill existing destinations or not, defaults
            to false
            @type: bool
        """
        if reset and self.destinations is not None and \
                        len(self.destinations) > 0:
            self.terminate_threads(self.destinations)

        self.destinations = []

        for info in self.configManager.dests:
            # Dests should already include the dest parsed from the CLI/env
            # If there is not a valid dest parsed from the CLI/env we'll have
            # to create a dest with
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
            self.destinations.append(dest)

        if len(self.destinations) == 0:
            # Try to use the destination from the CLI / defaults if there is
            # a valid one
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
            self.destinations.append(dest)

    @staticmethod
    def wait_on_threads(threads, max_wait_time=None, kill_on_timeout=False):
        """
        Wait for each of the threads in the list to be terminated
        @param threads: A list of IntervalThread objects to wait on
        @type threads: list

        @param max_wait_time: An optional max amount of seconds to wait
        @type max_wait_time: int

        @param kill_on_timeout: An optional arg that, if truthy and
        max_wait_time is defined and exceeded, cause this method to attempt
        to terminate and join the threads given it.
        @type kill_on_timeout: bool

        @return: A list of threads that have not quit yet. Without a
        max_wait_time this list is always empty (or we are stuck waiting).
        With a max_wait_time this list will include those threads that have
        not quit yet.
        @rtype: list
        """
        total_waited = 0
        threads_not_terminated = list(threads)
        while len(threads_not_terminated) > 0:
            if max_wait_time is not None and total_waited > max_wait_time:
                if kill_on_timeout:
                    Executor.terminate_threads(threads_not_terminated)
                    return []
                return threads_not_terminated
            time.sleep(1)
            total_waited += 1
            for thread in threads:
                if thread.is_terminated():
                    threads_not_terminated.remove(thread)
        return threads_not_terminated

    @staticmethod
    def terminate_threads(threads):
        for thread in threads:
            thread.stop()
            thread.join()

    def run_oneshot(self):
        # Start all sources
        self._create_virt_backends()

        if len(self.virts) == 0:
            err = "virt-who can't be started: no suitable virt backend found"
            self.logger.error(err)
            self.stop_threads()
            sys.exit(err)

        self._create_destinations()

        if len(self.destinations) == 0:
            err = "virt-who can't be started: no suitable destinations found"
            self.logger.error(err)
            self.stop_threads()
            sys.exit(err)

        for thread in self.virts:
            thread.start()

        Executor.wait_on_threads(self.virts)

        if self.options.print_:
            to_print = {}
            for source in self.configManager.sources:
                try:
                    report = self.datastore.get(source)
                    config = report.config
                    to_print[config] = report
                except KeyError:
                    self.logger.info('Unable to retrieve report for source '
                                     '\"%s\" for printing' % source)
            return to_print

        for thread in self.destinations:
            thread.start()

        Executor.wait_on_threads(self.destinations)

    def run(self):
        self.reloading = False
        self.logger.debug("Starting infinite loop with %d seconds interval", self.options.interval)

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
        print "STOPPING ALL (non-main) THREADS"
        if self.terminate_event.is_set():
            return
        self.terminate_event.set()
        self.terminate_threads(self.virts)
        self.virts = []
        self.terminate_threads(self.destinations)
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
