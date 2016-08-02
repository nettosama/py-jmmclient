py-jmmclient
========

Hacked together https://github.com/ernw/python-wcfbin and https://github.com/cackharot/suds-py3 to work with:

https://github.com/japanesemediamanager/jmmserver

Main usage:

```python
import jmmclient

jmmclient.call_service('ScanDropFolders', '192.168.1.50', '8111')

```

TODO:

A lot.