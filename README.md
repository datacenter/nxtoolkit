# nxtoolkit [![Documentation Status](https://readthedocs.org/projects/nxtoolkit/badge/?version=latest)](https://readthedocs.org/projects/nxtoolkit/?badge=latest) [![Build Status](https://api.shippable.com/projects/54ea96315ab6cc13528d52ad/badge?branchName=master)](https://app.shippable.com/projects/54ea96315ab6cc13528d52ad/builds/latest) [![Code Health](https://landscape.io/github/datacenter/nxtoolkit/master/landscape.svg?style=flat)](https://landscape.io/github/datacenter/nxtoolkit/master)


# Description

The NX Toolkit is a set of python libraries that allow basic
configuration of the Cisco Nexus Switch. It is intended to allow users to quickly begin using the REST API and accelerate the learning curve necessary to begin using the Switch.

The full documentation is published at the following link:
[http://datacenter.github.io/nxtoolkit/](http://datacenter.github.io/nxtoolkit/)


# Installation

## Environment

Required

* Python 2.7+
* [setuptools package](https://pypi.python.org/pypi/setuptools)
* NXOS version: 7.0(3)I2(1)

## Downloading

Option A:

If you have git installed, clone the repository

    git clone https://github.com/datacenter/nxtoolkit.git

Option B:

If you don't have git, [download a zip copy of the repository](https://github.com/datacenter/nxtoolkit/archive/master.zip) and extract.

Option C:

The latest build of this project is also available as a Docker image from Docker Hub

    docker pull dockercisco/nxtoolkit 

## Installing

After downloading, install using setuptools.

    cd nxtoolkit
    python setup.py install

If you plan on modifying the actual toolkit files, you should install the developer environment that will link the package installation to your development directory.

    cd nxtoolkit
    python setup.py develop

# Usage

A tutorial and overview of the nxtoolkit object model can be found in
the Documentation section found at
[http://datacenter.github.io/nxtoolkit/](http://datacenter.github.io/nxtoolkit/)

# License

Copyright 2015 Cisco Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
