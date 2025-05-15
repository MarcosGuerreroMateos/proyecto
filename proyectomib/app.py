from flask import Flask, render_template, request
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, getCmd, nextCmd, setCmd, bulkCmd
)
from pysnmp.proto.rfc1902 import Integer, OctetString

app = Flask(__name__)

OID_LIST = [
    ("1.3.6.1.2.1.1.1", "sysDescr"),
    ("1.3.6.1.2.1.1.5", "sysName"),
    ("1.3.6.1.2.1.1.3", "sysUpTime"),
    ("1.3.6.1.2.1.2.2.1.2", "ifDescr"),
]

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", oid_list=OID_LIST)

@app.route("/snmp", methods=["POST"])
def snmp():
    ip = request.form["ip"]
    community = request.form["community"]
    oid = request.form["oid"]
    operation = request.form["operation"]
    value = request.form.get("value")
    value_type = request.form.get("value_type")

    print(f"\n-- Nueva operación SNMP --")
    print(f"Operación: {operation}")
    print(f"IP agente: {ip}")
    print(f"Community: {community}")
    print(f"OID: {oid}")

    if operation == "set":
        print(f"Valor para setear: {value} (Tipo: {value_type})")

    if operation != "bulkwalk" and not oid.endswith(".0"):
        oid += ".0"

    result = []

    try:
        if operation == "get":
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
        elif operation == "next":
            iterator = nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            )
        elif operation == "bulkwalk":
            iterator = bulkCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                0, 10,
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            )
        elif operation == "set":
            if value_type == "Integer":
                typed_value = Integer(int(value))
            else:
                typed_value = OctetString(value)
            iterator = setCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(oid), typed_value)
            )
        else:
            result.append("Operación no reconocida.")
            print("Operación no reconocida.")
            return render_template("result.html", result=result)

        for response in iterator:
            errorIndication, errorStatus, errorIndex, varBinds = response
            if errorIndication:
                result.append(f"Error: {errorIndication}")
                print(f"Error: {errorIndication}")
                break
            elif errorStatus:
                err_msg = f"Error: {errorStatus.prettyPrint()} at {errorIndex}"
                result.append(err_msg)
                print(err_msg)
                break
            else:
                for varBind in varBinds:
                    line = f"{varBind[0]} = {varBind[1]}"
                    result.append(line)
                    print(line)
    except Exception as e:
        error_msg = f"Excepción: {e}"
        result.append(error_msg)
        print(error_msg)

    return render_template("result.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
