# CC8 — Laboratorio 09: SpeedTest (Raw Sockets TCP)

Implementación en **lenguaje C puro** de un benchmark de rendimiento de red tipo *Speedtest* utilizando **RAW Sockets** para construir y gestionar manualmente toda la secuencia del protocolo TCP a nivel de headers IPv4 y TCP.

---

## 1. Objetivos del Laboratorio

1. **Comprender la estructura y secuencia de los headers TCP e IPv4**:
   - Construcción manual de paquetes TCP (`SYN`, `ACK`, `PSH`, `FIN`) y cabeceras IPv4.
   - Cálculo de checksums de Internet (RFC 793) y pseudo-header TCP.
2. **Medición de rendimiento en 3 etapas**:
   - **Etapa 1 (Latencia)**: Medición directa de tiempo de ida y vuelta (RTT) mediante ICMP Ping implementado en C.
   - **Etapa 2 (Handshake y Transmisión con RAW Sockets)**: Establecimiento de sesión TCP (`3-way Handshake`) y transmisión de un archivo de **1 KB (1024 bytes)** repetido **10 veces consecutivas** sobre la misma conexión TCP activa.
   - **Etapa 3 (Cálculo de Velocidad de Transmisión)**: Cálculo de RTT promedio, tiempo total de ciclo y velocidad de subida (*Upload Speed*) según el modelo teórico del laboratorio y el rendimiento real obtenido.

---

## 2. Modelos Matemáticos y Fórmulas del Laboratorio

### 2.1 Tiempo Total de Transmisión
El proceso inicia con una conexión TCP que incurre en un RTT inicial ($RTT_{\text{handshake}}$). Luego, la transmisión de cada archivo incurre en un RTT más el tiempo de transmisión:

$$\text{Total Time} = \text{RTT} + (\text{RTT} + \text{transmit time})$$

### 2.2 Velocidad de Transmisión Simple (Fórmula del Laboratorio)
La velocidad simple se define en función del tamaño de ventana/archivo y el tiempo de ciclo:

$$\text{Speed} = \frac{\text{windowSize}}{\sim\text{RTT}}$$

**Ejemplo de referencia del enunciado:**
Transmitiendo un archivo de 1 KB con un RTT asumido constante de $32\text{ ms}$ ($0.032\text{ s}$):

$$\text{Speed} = \frac{1000 \times 8}{2 \times 0.032} = \frac{8000}{0.064} = 125\text{ kbps}$$

El programa evalúa tanto el valor decimal ($1000\text{ bytes} \times 8 = 8000\text{ bits}$) como el valor exacto del payload de prueba ($1024\text{ bytes} \times 8 = 8192\text{ bits}$) con el RTT medido empíricamente.

### 2.3 Throughput Real Efectivo (Wall-Clock)
Para contrastar el modelo teórico con la transferencia real:

$$\text{Throughput}_{\text{real}} = \frac{10 \times \text{Tamaño Archivo (bits)}}{\text{Tiempo Total de Transferencia (s)}}$$

---

## 3. Arquitectura del Proyecto (100% C)

```
lab09-speedtest/
├── Makefile                 # Automatización de compilación (macOS / Linux)
├── README.md                # Documentación completa y guía de ejecución
├── run_speedtest.sh         # Script de ejecución automatizada con tcpdump y pf/iptables
├── assets/
│   └── 1kb-image            # Archivo binario de prueba de exactamente 1024 bytes (1 KB)
├── include/
│   ├── checksum.h           # Funciones de checksum IPv4 y pseudo-header TCP
│   ├── ip_header.h          # Definición de cabecera IPv4 y constructor
│   ├── tcp_header.h         # Definición de cabecera TCP y constructor
│   ├── raw_socket.h         # Capa de abstracción de sockets raw (macOS pcap / Linux)
│   ├── ping.h               # Medidor de latencia ICMP en C
│   ├── logger.h             # Logger con formato de segmentos TCP y colores ANSI
│   └── speedtest.h          # Estructuras de sesión, métricas y prototipos
└── src/
    ├── checksum.c           # Algoritmo de checksum de complemento a 1
    ├── ip_header.c          # Constructor de IP (maneja byte-order BSD vs Linux)
    ├── tcp_header.c         # Constructor de segmentos TCP
    ├── raw_socket.c         # Enchufe de sockets raw y captura
    ├── ping.c               # Implementación de Ping ICMP nativo en C
    ├── logger.c             # Formateo de paquetes y resumen
    ├── speedtest_client.c   # Cliente principal Raw Sockets (las 3 etapas)
    └── speedtest_server.c   # Servidor TCP en C para el endpoint receptor
```

---

## 4. Requisitos del Sistema

- **Compilador**: `gcc` o `clang` con soporte para C99 / C11.
- **Herramientas de red**: `tcpdump`, `make`.
- **Plataformas soportadas**:
  - **macOS** (utiliza `libpcap` nativo incluido en el sistema y `pfctl` para suprimir RST del kernel).
  - **Linux** (utiliza sockets raw nativos y `iptables`).
- **Permisos**: Requiere privilegios de superusuario (`sudo`) únicamente para abrir el socket raw y capturar paquetes.

---

## 5. Compilación

Para compilar tanto el cliente como el servidor:

```bash
make
```

Para limpiar los binarios compilados:

```bash
make clean
```

Para empaquetar el proyecto en el archivo `.zip` para entrega en GES:

```bash
make zip
```

---

## 6. Ejecución

### Opción A: Ejecución Automatizada (Recomendada)

El script `run_speedtest.sh` se encarga de todo el ciclo de vida:
1. Compila los binarios en C.
2. Configura temporalmente el firewall (`pf` en macOS o `iptables` en Linux) para evitar que el kernel envíe paquetes `RST` automáticos.
3. Inicia el servidor de prueba `speedtest_server` en segundo plano en el puerto 5001.
4. Inicia `tcpdump` para registrar todo el tráfico en `speedtest.pcap`.
5. Ejecuta `speedtest_client` con sudo, realizando las 3 etapas y guardando el log en `speedtest.log`.
6. Detiene `tcpdump`, muestra el análisis del flujo de paquetes capturados y restaura el firewall a su estado original.

```bash
./run_speedtest.sh
```

Parámetros opcionales:
- `-p <puerto>`: Especificar puerto TCP (por defecto: 5001).
- `-i <interfaz>`: Especificar interfaz de captura (por defecto `lo0` en macOS o `lo` en Linux).
- `--keep-server`: Mantiene el servidor activo al finalizar la prueba.

---

### Opción B: Ejecución Manual Paso a Paso

#### 1. Configurar regla para suprimir TCP RST del kernel
Cuando un socket raw envía paquetes TCP desde un puerto efímero sin que el kernel tenga un socket estándar asociado, el kernel del sistema operativo responde con un paquete `RST` que abortaría la conexión. Para evitarlo:

En **macOS**:
```bash
echo 'block drop out proto tcp from any port 40000:49999 flags R/R' | sudo pfctl -f -
sudo pfctl -e
```

En **Linux**:
```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 40000:49999 -j DROP
```

#### 2. Iniciar el Servidor TCP (Terminal 1)
```bash
./build/speedtest_server -p 5001
```

#### 3. Iniciar tcpdump para inspeccionar el flujo (Terminal 2)
```bash
sudo tcpdump -i lo0 -nn "tcp port 5001"
```

#### 4. Ejecutar el Cliente Raw Socket (Terminal 3)
```bash
sudo ./build/speedtest_client -l 127.0.0.1 -s 127.0.0.1 -p 5001 -f assets/1kb-image -i lo0
```

#### 5. Restaurar el firewall al finalizar
En **macOS**:
```bash
sudo pfctl -f /etc/pf.conf
```
En **Linux**:
```bash
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST --sport 40000:49999 -j DROP
```

---

## 7. Flujo de Paquetes TCP y Flags

Durante la ejecución, se observa en `tcpdump` y en el log de la aplicación la secuencia estricta del protocolo TCP:

```text
1. Handshake TCP (3-Way):
   Client -> Server  [SYN]      SEQ=X ACK=0
   Server -> Client  [SYN, ACK] SEQ=Y ACK=X+1    <-- Se calcula Initial RTT
   Client -> Server  [ACK]      SEQ=X+1 ACK=Y+1

2. Transmisión de Archivos (10 iteraciones sobre la misma conexión):
   Para cada transferencia i (1..10):
     Client -> Server  [PSH, ACK] SEQ=X_i ACK=Y_i LEN=1024 DATA=(1 KB payload)
     Server -> Client  [PSH, ACK] SEQ=Y_i ACK=X_i+1024 LEN=4 DATA="ACK\n"  <-- Se calcula RTT_i
     Client -> Server  [ACK]      SEQ=X_i+1024 ACK=Y_i+4

3. Cierre de Conexión (Connection Teardown):
   Client -> Server  [FIN, ACK] SEQ=Final ACK=Final
   Server -> Client  [ACK]      SEQ=... ACK=Final+1
   Server -> Client  [FIN, ACK] SEQ=... ACK=Final+1
   Client -> Server  [ACK]      SEQ=Final+1 ACK=Server_Fin+1
```

---

## 8. Ejemplo de Salida del Programa

```text
╔════════════════════════════════════════════════════════════╗
║ SPEEDTEST: RAW SOCKETS TCP BENCHMARK                       ║
║ 3 Stages: Latency, RAW TCP Handshake, 10x 1KB File Upload  ║
╚════════════════════════════════════════════════════════════╝

---------- STAGE 1: LATENCY MEASUREMENT (ICMP PING) ----------
2026-10-18 09:20:00.123 speedtest_client.c: Pinging target 127.0.0.1 (4 probes)...
2026-10-18 09:20:00.340 speedtest_client.c: Ping Success: Sent=4, Received=4, Min=0.145 ms, Avg=0.180 ms, Max=0.220 ms
2026-10-18 09:20:00.341 speedtest_client.c: Loaded payload: 1024 bytes from 'assets/1kb-image'

---------- STAGE 2: TCP 3-WAY HANDSHAKE (RAW SOCKET) ----------
Client -> Server [SYN] SEQ=1829472190
Server -> Client [SYN, ACK] SEQ=4192847101 ACK=1829472191
2026-10-18 09:20:00.345 speedtest_client.c: Initial Handshake RTT: 0.850 ms (SYN -> SYN+ACK)
Client -> Server [ACK] SEQ=1829472191 ACK=4192847102

---------- STAGE 2: 10x 1KB FILE TRANSMISSION OVER RAW TCP ----------
-> File Transfer  1/10: RTT =   0.450 ms | SEQ=1829472191 ACK=1829473215
-> File Transfer  2/10: RTT =   0.420 ms | SEQ=1829473215 ACK=1829474239
-> File Transfer  3/10: RTT =   0.410 ms | SEQ=1829474239 ACK=1829475263
...
-> File Transfer 10/10: RTT =   0.430 ms | SEQ=1829481407 ACK=1829482431

---------- TCP CONNECTION TEARDOWN ----------
Client -> Server [FIN, ACK] SEQ=1829482431 ACK=...
Server -> Client [FIN, ACK] SEQ=... ACK=1829482432
Client -> Server [ACK] SEQ=1829482432 ACK=...

======================================================================
                    SPEEDTEST PERFORMANCE SUMMARY                     
======================================================================
 [STAGE 1] Latency Measurement (ICMP Ping)
   * Measured Ping Latency:                0.180 ms
----------------------------------------------------------------------
 [STAGE 2] TCP RAW Connection & Transmission
   * Initial TCP Handshake RTT:            0.850 ms  (SYN -> SYN+ACK)
   * Payload per Transfer:                  1024 bytes (1 KB)
   * Transfers Completed:                     10 transfers
   * Total Bytes Transmitted:              10240 bytes
   * Transfer RTT (Min):                   0.410 ms
   * Transfer RTT (Average):               0.435 ms
   * Transfer RTT (Max):                   0.490 ms
   * Total Wall-Clock Elapsed Time:      115.200 ms
----------------------------------------------------------------------
 [STAGE 3] Speed Calculations (Lab Specification)
   * Formula: Total Time = RTT + (RTT + transmit time)
     Total Cycle Time:                     1.285 ms  (Initial RTT + Avg Transfer RTT)
     Assumed Cycle (2 * Avg RTT):          0.870 ms

   * Formula Speed (Decimal 1000 B, 2 * RTT):
     Speed = (1000 * 8) / (2 * 0.000435 s) =    9195.40 kbps (  9.20 Mbps)

   * Formula Speed (Binary 1024 B, 2 * RTT):
     Speed = (1024 * 8) / (2 * 0.000435 s) =    9416.09 kbps (  9.42 Mbps)

   * Effective Upload Throughput (Actual Wall-Clock):
     Throughput = (10240 * 8) / (0.115200 s) =   711.11 kbps (  0.71 Mbps)
======================================================================
```
