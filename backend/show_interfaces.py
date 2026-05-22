from scapy.arch.windows import get_windows_if_list

interfaces = get_windows_if_list()

for i in interfaces:

    print(
        "Name:",
        i.get("name")
    )

    print(
        "GUID:",
        i.get("guid")
    )

    print(
        "-"*40
    )