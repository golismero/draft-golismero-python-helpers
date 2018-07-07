"""
This file contains helpers to interact with the operating system
"""
import os
import logging
import subprocess

from typing import List

from .exceptions import *

log = logging.getLogger("golismero3")


def launch_command(command: str,
                   callback: callable or List[callable],
                   file_result: str = None) -> Golismero3Exception or str:
    """
    This function launch a operating system command and call a list of
    callback for each line that commands write into the output.

    Usage example:

    >>> launch_command("nmap -oX /tmp/results.xml 127.0.0.1", \
                       callback=[print], file_result="/tmp/results.xml")
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE nmaprun><?xml-stylesheet
    href="file:///usr/local/bin/../share/nmap/nmap.xsl" [...]'

    :param command: command to launch in the system
    :param callback: function or list of functions to call each time a tools
            execution returns a new line
    :param file_result: if available, read the execution result from this file

    """
    # -------------------------------------------------------------------------
    # If result file already exits, remove if
    # -------------------------------------------------------------------------
    if file_result and os.path.exists(file_result):
        log.filter(f"Removing old results file: '{file_result}'")
        os.remove(file_result)

    # Start process
    popen = subprocess.Popen([*command.split(" ")],
                             stdout=subprocess.PIPE,
                             universal_newlines=True)

    output_result = []
    # Wait until program finishes
    for stdout_line in iter(popen.stdout.readline, ""):

        #
        # Notify to callback?
        #
        if callback:
            if hasattr(callback, "__iter__"):
                for f in callback:
                    f(stdout_line)
            else:
                callback(stdout_line)

        output_result.append(stdout_line)

    # Wait for process finishes
    popen.stdout.close()
    popen.wait()

    if file_result:
        try:
            with open(file_result, "r") as f:
                results = f.read()
        except IOError:
            raise Golismero3FileNotFoundException(
                f"file '{file_result}' not found to get results"
            )
    else:
        results = "\n".join(output_result)

    return results


__all__ = ('launch_command',)
