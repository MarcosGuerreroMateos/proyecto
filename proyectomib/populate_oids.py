import mysql.connector

# Configura aquí tu conexión
conn = mysql.connector.connect(
    host="192.168.56.101",      # IP de la VM con MariaDB
    user="mibuser_mm",          # Usuario con permisos
    password="1234",            # Contraseña correcta
    database="mib_mg"           # Nombre de tu base de datos
)

cursor = conn.cursor()
total, insertados, duplicados = 0, 0, 0

with open("oids.txt", "r") as file:
    for line in file:
        if "::" in line:
            try:
                parts = line.strip().split()
                if len(parts) == 2:
                    nombre_oid = parts[0]
                    oid = parts[1]
                    cursor.execute(
                        "INSERT IGNORE INTO oids (oid, traduccio_oid) VALUES (%s, %s)",
                        (oid, nombre_oid)
                    )
                    if cursor.rowcount:
                        insertados += 1
                    else:
                        duplicados += 1
                    total += 1
            except Exception as e:
                print(f"Error amb la línia: {line.strip()} → {e}")

conn.commit()
cursor.close()
conn.close()

print(f"OIDs processats: {total}, inserits: {insertados}, duplicats ignorats: {duplicados}")