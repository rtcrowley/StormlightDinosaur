# StormlightDinosaur
A Defensive C# app with the goal to give the user a basic intrusion detection overview of their Windows system. Simply for standalone Windows machines.

Runs through the following:

* RunKeys & Startup Folder enumeration
* Lsass & svchost process integrity
* Scheduled task & Service anomalies
* Active BITS jobs
* Potential persistence via WMI event subscriptions & Netsh DLL helpers
* More to come...

![alt text](https://rtcrowley.github.io/stdino.png?raw=true "execute")

**NOTES:** Targeted towards Windows 10 workstations, build as x64 and run as Administrator

