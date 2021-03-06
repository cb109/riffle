# :coding: utf-8
# :copyright: Copyright (c) 2014 Martin Pengelly-Phillips
# :license: See LICENSE.txt.

import sys

from PySide import QtGui

import riffle.browser


def main(arguments=None):
    '''Interactive test of custom filesystem browser.'''
    if arguments is None:
        arguments = sys.argv

    application = QtGui.QApplication(arguments)

    browser = riffle.browser.FilesystemBrowser()
    browser.setMinimumSize(600, 300)
    if browser.exec_():
        selected = browser.selected()
        print('Selected: {0}'.format(selected))

    sys.exit(application.exec_())


if __name__ == '__main__':
    raise SystemExit(main())

