# Anti Debug For Python
This module stops people from tying to debug your program, from running on a vm and from scanning the behaviour using virustotal or another environment

The Module Will Attempt To
- Check the ip of the host.
- Check the storage, ram and cpu counts.
- Check for virtual machine files/services/dll's/registry keys.
- Check if any debugging programs are open.
- Force close if any of the flags are met.

To use the module

First, install the requirements
```bash
pip install -r requirements.txt
```
Then initialize the script from your program
```python
from antiDebug import watchdog

watchdog()
print('Anti Debug Initialized')
```