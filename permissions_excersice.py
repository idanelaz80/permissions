import win32security as WINSEC
import win32api

pID = input("Enter process ID")


token = WINSEC.OpenProcessToken(
    win32api.GetCurrentProcess(),
    WINSEC.TOKEN_QUERY
)

# Get the privileges
privileges = WINSEC.GetTokenInformation(
    token, WINSEC.TokenPrivileges
)


for luid, attributes in privileges:
    name = WINSEC.LookupPrivilegeName(None, luid)
    try:
        if attributes and WINSEC.SE_PRIVILEGE_ENABLED:
            per = "enabled"
        else:
            per = "disabled"
        print(name, per)
    except:
        pass