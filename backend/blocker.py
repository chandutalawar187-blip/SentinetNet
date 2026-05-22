import os

def block_ip(ip):

    if ip == "127.0.0.1":
        return

    cmd = (

        f'netsh advfirewall firewall '

        f'add rule '

        f'name="SentinelBlock_{ip}" '

        f'dir=in '

        f'action=block '

        f'remoteip={ip}'

    )

    os.system(cmd)

    print(
        f"Blocked {ip}"
    )