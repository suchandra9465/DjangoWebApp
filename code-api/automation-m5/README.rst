Automation M5
=================

This project is a simple CLI app that gets the SonicWall configurations and generate the PaloAulto configuration for destination IP.

It runs under officially Django `supported versions <https://www.djangoproject.com/download/#supported-versions>`_:

* Django 1.8, Django 1.9 and Django 1.10
* Python 3 (3.2, 3.4, 3.5, 3.6)

This app is still under development.


Directory layout
================

AutomationM5 directory structure looks as follows::

    AutomationM5/
    |-- docs
    |-- extra
    |   |-- demo
    |       |-- templates
    |-- generator
        |-- network
        |   |-- paloaulto
        |   |-- sonicwall
        |-- tests
        |   |-- templates
        |-- templates

The 3 root level directories separate the **docs**, the **CLI project** and the  **code**.

The root level directory contains the following files::

    sonicwall-to-paloaulto-automation/
    |-- LICENSE
    |-- MANIFEST.in
    |-- AUTHORS
    |-- README.md
    |-- requirements.pip
    |-- requirements_tests.pip
    |-- setup.py


The ``setup.py`` file
=====================

Additionally to the common setup content the ``setup.py`` file provides a hook to run the app's tests suite::

    ...
    from setuptools.command.test import test

    def run_tests(*args):
        from sample_app.tests import run_tests
        errors = run_tests()
        if errors:
            sys.exit(1)
        else:
            sys.exit(0)

    test.run_tests = run_tests

Which allows to run the tests with the test command argument::

    $ python setup.py test

Look at the code of the function ``run_tests`` defined in ``sample_app.tests.__init__.py`` to know the details on how Django gets setup to run the tests suite.


The docs directory
==================

Use `sphinx <http://sphinx-doc.org/>`_ to initialize the content of this directory. Run the following command and answer the questions. Sphinx will create the necessary content to allow you to start writing your docs right away::

    $ cd docs/
    $ sphinx-quickstart

To produce automatic documentation of your modules sphinx-build needs to reach out Django, your app's code and everything that happens to be imported in between. The ``conf.py`` file in ``django-sample-app/docs`` comes with code that activates the virtualenv in which the app has been developed. By activating the virtualenv in ``conf.py`` sphinx-build will reach out the modules. 

Adapt the code to point to the path of your ``bin/activate_this.py`` script in your virtualenv, or comment it out if you won't use it to avoid building errors. The code in ``conf.py`` that activate the virtualenv::

    ...
    import sys, os

    venv_path = os.path.abspath(os.path.join('..', '..'))
    activate_this = os.path.join(venv_path, 'bin/activate_this.py')
    execfile(activate_this, dict(__file__=activate_this))
    sys.path.insert(0, os.path.abspath(os.path.pardir))
    ...

