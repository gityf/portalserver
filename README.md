PortalServer
========

PortalServer is a Go server implementing the PORTAL protocol. It provides functions for Marshalling & Unmarshalling PORTAL packets. The packet processing logic resides with the application using the server.
It implementing  the portal2.0 protocol and work well with HUAWEI bras and ZTE bras.

**NOTE**: This is a Work-In-Progress. A lot of will change in the coming days, and I recommend against using this in production code as API might change. Patches are welcome!

Web API
---
There are three api for web caller.
`/portalserver/login ` is login api,  input params  of username,password,userip and brasip  should be  exist in request package.
`/portalserver/logout` is logout api,  input params  of username,userip and brasip  should be  exist in request package.
`/portalserver/getvlaninfo` is getvlaninfo api,  input params  of username,userip and brasip  should be  exist in request package.

LICENSE
-------

This library is under Apache License, Version 2.0. For more details please see LICENSE file.

Copyright
---------

Copyright (C) 2016 Wang Yaofu. All rights reserved.
