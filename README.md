# RoLaGuard Community Edition
​
## Backend
This repository contains the source code of RoLaGuard backend. This module serves requests from the frontend, data-collectors and engine using an API. Also it provides communication via web sockets to the frontend, and makes use of message queues to notify events to the data-collectors module.

To access the main project with instructions to easily run the rolaguard locally visit the [RoLaGuard](./../README.md) repository. For contributions, please visit the [CONTRIBUTIONS](./../CONTRIBUTING.MD) file.
​
### Build
​
Build a docker image locally:
```
docker build -t rolaguard-backend .
```