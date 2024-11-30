import asyncio
from pysnmp.hlapi.v3arch.asyncio import *


async def run():
    snmpEngine = SnmpEngine()
    while True:
        errorIndication, errorStatus, errorIndex, varBindTable = await bulk_cmd(
            snmpEngine,
            CommunityData("public", mpModel=1),
            await UdpTransportTarget.create(("demo.pysnmp.com", 161)),
            ContextData(),
            0,
            50,
            ObjectType(ObjectIdentity('1.3.6.1.2.1.4.24.4')),
        )

        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print(
                f"{errorStatus.prettyPrint()} at {varBinds[int(errorIndex) - 1][0] if errorIndex else '?'}"
            )
        else:
            for varBind in varBindTable:
                print(" = ".join([x.prettyPrint() for x in varBind]))

        varBinds = varBindTable
        if is_end_of_mib(varBinds):
            break
    return


asyncio.run(
    run()
)