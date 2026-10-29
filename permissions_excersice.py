
import win32security as WINSEC
import win32api
import win32con
import sys


def get_token_privileges(PID):
    """
    Prints all privileges of a process and their status.

    :param PID: The process ID whose privileges will be displayed.
    :return: None
    """

    process = win32api.OpenProcess(
        win32con.PROCESS_QUERY_INFORMATION,
        False,
        PID
    )

    token = WINSEC.OpenProcessToken(
        process,
        WINSEC.TOKEN_QUERY
    )

    privileges = WINSEC.GetTokenInformation(
        token, WINSEC.TokenPrivileges
    )

    for luid, attributes in privileges:
        try:
            name = WINSEC.LookupPrivilegeName(None, luid)

            if attributes & WINSEC.SE_PRIVILEGE_ENABLED:
                per = "enabled"
            else:
                per = "disabled"

            print(name, per)

        except Exception:
            pass

    win32api.CloseHandle(token)
    win32api.CloseHandle(process)


def enable_privilege(PID, privilege_name):
    """
    attempts to enable a privilege in a process's access token

    :param PID: the process ID whose token will be modified
    :param privilege_name: The name of the privilege to enable
    :return: None
    """
    process = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION,False,PID)

    token = WINSEC.OpenProcessToken(process,WINSEC.TOKEN_QUERY | WINSEC.TOKEN_ADJUST_PRIVILEGES)

    try:
        luid = WINSEC.LookupPrivilegeValue(None, privilege_name)

        WINSEC.AdjustTokenPrivileges(token,False, [(luid, WINSEC.SE_PRIVILEGE_ENABLED)])

        print("Privilege adjustment requested:", privilege_name)

    finally:
        win32api.CloseHandle(token)
        win32api.CloseHandle(process)


if len(sys.argv) != 3:
    print("Usage: python main.py <PID> <Privilege>")
    sys.exit(1)

PID = int(sys.argv[1])
privilege_name = sys.argv[2]

try:
    print("Privileges before:")
    get_token_privileges(PID)

    print("\nEnabling privilege:")
    enable_privilege(PID, privilege_name)

    print("\nPrivileges after:")
    get_token_privileges(PID)

except Exception as e:
    print("Error:", e)
