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

    def check_report_state(self, report):
        ''' Check state of one report that is being processed on server. '''
        manager = Manager.fromOptions(self.logger, self.options, report.config)
        manager.check_report_state(report)

    def check_reports_state(self):
        ''' Check status of the reports that are being processed on server. '''
        if not self.reports_in_progress:
            return
        updated = []
        for report in self.reports_in_progress:
            self.check_report_state(report)
            if report.state == AbstractVirtReport.STATE_CREATED:
                self.logger.warning("Can't check status of report that is not yet sent")
            elif report.state == AbstractVirtReport.STATE_PROCESSING:
                updated.append(report)
            else:
                self.report_done(report)
        self.reports_in_progress = updated

    def send_current_report(self):
        name, report = self.queued_reports.popitem(last=False)
        return self.send_report(name, report)

    def send_report(self, name, report):
        try:
            if self.send(report):
                # Success will reset the 429 count
                if self._429_count > 0:
                    self._429_count = 1
                    self.retry_after = MinimumSendInterval

                self.logger.debug('Report for config "%s" sent', name)
                if report.state == AbstractVirtReport.STATE_PROCESSING:
                    self.reports_in_progress.append(report)
                else:
                    self.report_done(report)
            else:
                report.state = AbstractVirtReport.STATE_FAILED
                self.logger.debug('Report from "%s" failed to sent', name)
                self.report_done(report)
        except ManagerThrottleError as e:
            self.queued_reports[name] = report
            self._429_count += 1
            self.retry_after = max(MinimumSendInterval, e.retry_after * self._429_count)
            self.send_after = time.time() + self.retry_after
            self.logger.debug('429 received, waiting %s seconds until sending again', self.retry_after)

    def report_done(self, report):
        name = report.config.name
        self.send_after = time.time() + self.options.interval
        if report.state == AbstractVirtReport.STATE_FINISHED:
            self.last_reports_hash[name] = report.hash

        if self.options.oneshot:
            try:
                self.oneshot_remaining.remove(name)
            except KeyError:
                pass

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
            info.name = "Destination_%s" % len(self.destinations)
            logger = log.getLogger(name=info.name)
            manager = Manager.fromInfo(logger, self.options, info)
            info.name = "Destination_%s" % len(self.destinations)
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

        if len(self.destinations) <= 0:
            # Try to use the default destination (the one that the local system
            # is currently registered to.)
            self.logger.warning("No destinations found, using default")
            try:
                source_keys = list(self.configManager.sources)
                logger = log.getLogger(name="Default_Destination")
                manager = Manager.fromOptions(logger, self.options)
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
            result = all([thread.is_terminated() for thread in
                         self.destinations]) and all([thread.is_terminated() for
                                                     thread in self.virts])
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

def exceptionCheck(e):
    try:
        # This happens when connection to server is interrupted (CTRL+C or signal)
        if e.args[0] == errno.EALREADY:
            exit(0)
    except Exception:
        pass
