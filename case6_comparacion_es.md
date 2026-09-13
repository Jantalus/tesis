# Caso 6 — Comportamiento de una biblioteca de terceros sobre un buffer del llamador

## 1. Preguntas que queremos responder

El caso de estudio debe comenzar por las preguntas, porque las herramientas se
comparan según la información que necesitamos obtener.

### Pregunta 1 — ¿Qué accesos realiza la biblioteca?

Queremos saber:

- si la biblioteca accedió al buffer;
- si realizó lecturas o escrituras;
- qué direcciones fueron accedidas;
- cuántos bytes involucró cada acceso; y
- si algún acceso ocurrió fuera del rango asignado.

Esta pregunta busca recuperar la **huella de accesos** del buffer.

### Pregunta 2 — ¿Qué valores se leen o escriben y en qué orden?

Queremos saber, para cada operación:

```text
orden | operación | dirección | tamaño | bytes | instrucción | hilo
```

Esta pregunta busca recuperar una **traza semántica de valores**, no solamente
demostrar que una página fue tocada.

## 2. Herramientas utilizadas

Antes de describir el experimento, resumimos qué es cada herramienta y qué
papel cumple en la comparación:

- **TracerPIN:** herramienta basada en Intel PIN que permite filtrar accesos a
  una variable o región y registrar información detallada, incluidos valores
  escritos. Es la herramienta principal que estamos evaluando.

- **Frida:** plataforma de instrumentación dinámica. Permite interceptar una
  función y examinar sus argumentos sin modificar la biblioteca. En este caso
  se usa `MemoryAccessMonitor` para detectar si las páginas del buffer fueron
  accedidas.

- **Valgrind Lackey:** herramienta de trazado basada en la representación
  intermedia VEX de Valgrind. Registra lecturas y escrituras con sus
  direcciones y tamaños, aunque genera trazas muy grandes.

- **DynamoRIO:** plataforma de instrumentación binaria dinámica. Su cliente
  `drmemtrace` registra referencias de memoria junto con tamaño, instrucción e
  hilo. Además, el proyecto incluye `memval`, un ejemplo orientado a registrar
  valores escritos.

Ejemplos mínimos de uso:

```bash
### TracerPIN
Tracer -fname run_zlib -vname compressed -excl 0 \
       -o zlib.trace -- ./study

### Frida
frida -f ./study -l frida_monitor.js

### Valgrind Lackey
valgrind --tool=lackey --trace-mem=yes ./study 2> lackey.log

### DynamoRIO
drrun -t drmemtrace -offline -outdir dr_trace -- ./study
```

La diferencia central es que TracerPIN y una extensión de DynamoRIO pueden
orientarse a recuperar valores, mientras que Frida en su configuración básica
detecta páginas y Valgrind Lackey registra principalmente operaciones,
direcciones y tamaños.

## 3. Objetivo

El llamador entrega un buffer a una biblioteca cuyo código interno no quiere modificar ni analizar manualmente. Queremos observar qué posiciones lee y escribe, el orden, el tamaño de cada acceso, los valores leídos o escritos y los accesos fuera del rango.

El ejemplo usa `zlib::compress2()`. También usamos un control artificial (`known`) con una secuencia de escrituras conocida, para medir la exactitud de cada herramienta.

## 3.1. Código analizado

El programa de prueba contiene dos caminos. El primero genera una secuencia de
escrituras conocida:

```cpp
extern "C" void known_writes(unsigned char* dst) {
    dst[0] = 0x11;
    dst[1] = 0x22;
    *reinterpret_cast<std::uint32_t*>(dst + 4) = 0xAABBCCDD;
    for (int i = 8; i < 16; ++i)
        dst[i] = static_cast<unsigned char>(i);
    dst[8] = 0x99;
}
```

Este camino permite comparar cada traza con una respuesta conocida: esperamos
12 escrituras, incluyendo la sobrescritura de la posición `0x08`.

El segundo camino pasa un buffer propio a zlib:

```cpp
uLong output_size = static_cast<uLong>(capacity);
int result = compress2(compressed, &output_size,
                       input.data(), input.size(),
                       Z_DEFAULT_COMPRESSION);
```

Aquí no suponemos una secuencia interna concreta. La biblioteca es tratada
como una caja negra y observamos qué hace sobre `compressed`.

El programa también puede colocar bytes centinela antes y después del buffer y
realizar escrituras intencionalmente inválidas. Así podemos comprobar por
separado si una herramienta observa accesos fuera de rango.

## 3.2. Compilación y ejecución base

Compilamos el programa con información de depuración para facilitar la
identificación de funciones y variables:

```bash
g++ -O0 -g -gdwarf-4 -fno-omit-frame-pointer \
    -rdynamic study.cpp -lz -o study
```

Ejemplos mínimos:

```bash
./study known 16 64
./study zlib 4096 8192
```

El resultado informa la dirección del buffer, la capacidad, el resultado de
zlib, el tamaño comprimido y el estado de los bytes centinela.

## 4. Qué se necesita para responder las preguntas

### 4.1. TracerPIN

Para responder la pregunta 1, TracerPIN necesita instrumentar los accesos al
puntero que representa el buffer y conservar operación, dirección y tamaño.
Para detectar accesos fuera de rango, el filtro debe incluir también una región
de guardia o permitir que el rango observado sea mayor que el buffer esperado.

Para responder la pregunta 2, debe conservar además el orden y el valor de
cada operación. Esta es la parte en la que TracerPIN resulta más directo en
nuestra configuración: ya registró los valores de las escrituras.

### 4.2. Frida

Con `MemoryAccessMonitor`, Frida responde parcialmente la pregunta 1:
indica que una página fue accedida y proporciona operación, dirección,
instrucción e hilo. No garantiza todos los accesos al buffer ni distingue con
precisión bytes dentro y fuera del rango cuando la región comparte páginas.

Para esta comparación implementamos además `frida_value_trace.js`. Usa
`Stalker` para copiar las instrucciones, identifica operandos de memoria,
calcula la dirección efectiva y ejecuta un *callout* después de la
instrucción. El callout lee los bytes de la dirección observada y conserva el
orden junto con operación, dirección, tamaño, instrucción e hilo.

Esto responde la pregunta 2 para las instrucciones x86-64 cubiertas por este
prototipo. En una lectura registramos los bytes que estaban en memoria en el
operando; no registramos el valor interno de un registro después de la carga.
En una escritura, `bytes_after` permite verificar el valor que quedó escrito.

### 4.3. Valgrind Lackey

Con `--trace-mem=yes`, Lackey responde buena parte de la pregunta 1: informa
lecturas y escrituras, direcciones y tamaños. El análisis posterior debe
filtrar los accesos al rango de `compressed` y verificar las guardias.

Para responder la pregunta 2 hay que modificar Lackey o escribir una herramienta
Valgrind sobre VEX IR que capture el valor de las cargas y los almacenamientos.
La herramienta debe preservar el orden y tratar correctamente operaciones
vectoriales, instrucciones de cadenas y accesos divididos.

### 4.4. DynamoRIO

`drmemtrace` responde la pregunta 1 con referencias de lectura/escritura,
dirección y tamaño. También ofrece PC e hilo. Se necesita convertir la traza y
filtrar las referencias que intersectan el buffer y sus guardias.

Para responder la pregunta 2, el ejemplo oficial `memval_simple.c` ya ofrece
una base para capturar valores escritos. Habría que adaptarlo para filtrar
`compressed`, registrar lecturas y producir el formato común de la pregunta 2.

## 5. Matriz de cobertura

| Herramienta/configuración | Pregunta 1: accesos | Pregunta 2: valores y orden | Trabajo adicional |
| --- | --- | --- | --- |
| TracerPIN usado en el estudio | Sí, para el rango instrumentado | Sí para escrituras instrumentadas | PIN, DWARF y arquitectura; `-interior 1` para punteros interiores |
| Frida `MemoryAccessMonitor` | Parcial: páginas tocadas | No | Usar el prototipo de `Stalker` para obtener granularidad de instrucciones |
| Frida `Stalker` + `frida_value_trace.js` | Sí, para operandos x86-64 cubiertos | Sí, bytes del operando y orden | Endurecer el decodificador, cubrir otras arquitecturas/instrucciones y reducir el costo |
| Valgrind Lackey estándar | Sí: tipo, dirección y tamaño | No | Escribir/modificar una herramienta Valgrind sobre VEX IR |
| DynamoRIO `drmemtrace` estándar | Sí: tipo, dirección, tamaño, PC e hilo | No | Adaptar `memval` y agregar valores de lecturas |

La tabla distingue entre “puede observar accesos” y “puede reconstruir los
valores”. Una herramienta puede responder la primera pregunta sin responder la
segunda.

## 6. Comparación

| Herramienta | Información estándar | Extensión para valores | Dificultad estimada |
| --- | --- | --- | --- |
| **TracerPIN** | Accesos filtrados, dirección, operación y valor | `-interior 1`; opcionalmente `-interior-size` para limitar la sección | Baja-media; depende de PIN, DWARF y x86 |
| **Frida `MemoryAccessMonitor`** | Primer acceso por página, operación, dirección, instrucción e hilo | `Stalker` y un transformador que decodifique instrucciones y capture operandos | Alta; no es su uso principal |
| **Frida `Stalker` + prototipo** | Accesos a operandos de memoria, dirección, tamaño, instrucción e hilo | Ya captura bytes y orden para el caso x86-64 probado | Media-alta; es un prototipo específico de arquitectura |
| **Valgrind Lackey** | Lectura/escritura, dirección y tamaño | Modificar Lackey o escribir una herramienta Valgrind sobre VEX IR | Media-alta |
| **DynamoRIO `drmemtrace`** | Lectura/escritura, dirección, tamaño, PC e hilo | Usar/adaptar `memval_simple.c` y agregar filtrado de buffer y lecturas | Media |

## 6.1. Contexto y uso detallado de cada herramienta

### TracerPIN

TracerPIN es la herramienta bajo evaluación en este caso. Está construida
sobre Intel PIN y permite seleccionar una variable o un puntero observado,
registrando los accesos que ocurren sobre esa región. En nuestra configuración
usamos el filtro de variable `compressed` y desactivamos la exclusión del
código de biblioteca con `-excl 0`. Por eso se pueden observar las escrituras
realizadas desde el interior de zlib.

Uso mínimo representativo:

```bash
Tracer -fname run_zlib -vname compressed -excl 0 \
       -o zlib.trace -- ./study
```

En el experimento inicial usamos `STUDY_DIRECT=1` como workaround para que el
puntero filtrado coincidiera con la dirección exacta retornada por `malloc()`.
La extensión nueva permite usar el layout normal con guardias:

```bash
STUDY_MODE=zlib STUDY_INPUT=4096 STUDY_CAPACITY=8192 \
  Tracer -fname run_zlib -vname compressed \
  -interior 1 -interior-size 8192 -excl 0 \
  -o zlib_interior_guarded.trace -- ./study
```

`-interior-size` evita que el seguimiento de `compressed` abarque toda la
asignación que contiene las guardias.

### Frida

Frida es una plataforma de instrumentación dinámica que permite insertar
JavaScript en un proceso que ya está ejecutándose o que se inicia bajo su
control. Es especialmente útil para interceptar funciones y examinar sus
argumentos sin recompilar la biblioteca.

En este caso interceptamos `compress2()`, tomamos el primer argumento como
dirección del destino y el segundo como capacidad, y activamos
`MemoryAccessMonitor`:

```javascript
Interceptor.attach(compress2, {
    onEnter(args) {
        MemoryAccessMonitor.enable({
            base: args[0],
            size: args[1].readULong()
        }, { onAccess(details) {
            console.log(details.operation, details.address);
        }});
    }
});
```

Uso mínimo:

```bash
frida -f ./study -l frida_monitor.js
```

`MemoryAccessMonitor` informa el primer acceso a cada página monitoreada. Por
eso es adecuado para saber si una región fue tocada, pero no para recuperar
 todas las escrituras ni sus valores.

#### Extensión implementada para recuperar valores

Para contestar la segunda pregunta no nos quedamos con la capacidad básica de
Frida. Agregamos `case6_experiment/frida_value_trace.js`, un prototipo que
combina `Interceptor` y `Stalker`:

```javascript
const capturedAccess = operand.access === "w" ? "write" :
    operand.access === "rw" ? "readwrite" : "read";

iterator.putCallout(context => {
    recordAccess(context, instructionAddress,
                 capturedAccess, operand);
});
```

La ejecución utilizada fue:

```bash
STUDY_MODE=known STUDY_CAPACITY=64 STUDY_DIRECT=1 \
  frida -f ./study -l frida_value_trace.js

STUDY_MODE=zlib STUDY_INPUT=4096 STUDY_CAPACITY=8192 STUDY_DIRECT=1 \
  frida -f ./study -l frida_value_trace.js
```

En el control conocido recuperó las 12 escrituras esperadas, incluyendo la
sobrescritura final:

```text
0:11, 1:22, 4:ddccbbaa, 8:08, 9:09, ..., 15:0f, 8:99
```

En zlib recuperó 16 eventos sobre el buffer: 13 lecturas y 3 escrituras. Un
ejemplo de salida fue:

```json
{"operation":"write", "address":"...b400", "size":1,
 "bytes_after":"78"}
{"operation":"read", "address":"...b420", "size":32,
 "bytes_after":"6acbe243..."}
```

El nombre `bytes_after` es deliberado: el callback se ejecuta después de la
instrucción y lee la memoria. Para escrituras representa los bytes que quedaron
en el buffer. Para lecturas representa los bytes fuente observables en memoria,
que coinciden con el operando cargado en instrucciones normales, pero no prueba
qué transformación hizo luego la biblioteca sobre el valor en sus registros.

El resultado demuestra que Frida sí puede extenderse para responder esta
pregunta, pero ya no se trata de `MemoryAccessMonitor` estándar: requiere un
instrumentador de instrucciones específico para x86-64, cálculo de direcciones
efectivas, callouts JavaScript y una política para instrucciones especiales,
operaciones vectoriales, accesos divididos y concurrencia.

### Valgrind Lackey

Valgrind ejecuta el programa mediante una representación intermedia llamada
VEX IR y permite que sus herramientas inserten instrumentación durante la
ejecución. Lackey es una herramienta pequeña destinada, entre otras cosas, a
mostrar accesos de memoria.

Uso mínimo:

```bash
valgrind --tool=lackey --trace-mem=yes \
        ./study zlib 4096 8192 2> lackey.log
```

Lackey informa operaciones de lectura y escritura, direcciones y tamaños. La
salida es muy grande y no incluye directamente los bytes leídos o escritos.
Para obtener valores habría que modificar Lackey o escribir una herramienta
Valgrind propia que instrumente las expresiones de carga y almacenamiento del
VEX IR. [Documentación de herramientas Valgrind](https://valgrind.org/docs/manual/writing-tools.html)

### DynamoRIO y `drmemtrace`

DynamoRIO es una plataforma de instrumentación binaria dinámica. Su cliente
`drmemtrace` genera trazas de instrucciones y referencias de memoria, y puede
analizarlas posteriormente sin modificar el código fuente de zlib.

Uso mínimo:

```bash
drrun -t drmemtrace -offline \
      -outdir dr_trace -- ./study zlib 4096 8192
```

La traza estándar contiene tipo de acceso, dirección, tamaño, dirección de la
instrucción e hilo. En nuestro análisis tuvimos que convertir la traza raw y
filtrar las referencias que caían dentro de `compressed`.

El registro estándar no contiene los bytes del dato. [Estructura de referencias de memoria de DynamoRIO](https://dynamorio.org/structdynamorio_1_1drmemtrace_1_1__memref__data__t.html)

DynamoRIO incluye además el ejemplo oficial `memval_simple.c`, que registra
direcciones y valores escritos. Esto lo convierte en una base práctica para
construir una variante que filtre nuestro buffer y registre también lecturas.
[Ejemplo oficial `memval_simple.c`](https://github.com/DynamoRIO/dynamorio/blob/master/api/samples/memval_simple.c)

## 7. ¿TracerPIN es mejor?

Para el objetivo específico de este caso —obtener la secuencia de valores escritos por una biblioteca en un buffer del llamador—, **TracerPIN es la opción más directa de las comparadas**:

- ya registra valores escritos;
- permite filtrar por el buffer o variable de interés;
- no requiere modificar zlib; y
- conserva el orden de las operaciones instrumentadas.

Pero no es universalmente mejor:

- requiere una combinación específica de PIN, arquitectura y símbolos DWARF;
- en la configuración original el filtro dinámico necesitó el puntero exacto retornado por `malloc()`; la extensión `-interior 1` elimina esa limitación para este caso;
- su portabilidad y facilidad de instalación son peores que las de Frida; y
- Valgrind y DynamoRIO ofrecen una descripción más general de accesos, incluyendo lecturas, tamaños, instrucciones e hilos.

La conclusión correcta es: TracerPIN está mejor alineado con la pregunta “¿qué valores escribió esta biblioteca en mi buffer?”. Con la extensión `-interior 1` puede además seguir el buffer normal con guardias, y `-interior-size` permite limitar la sección lógica. DynamoRIO es la alternativa más prometedora si queremos construir una solución equivalente y más general. Valgrind también puede hacerlo, pero exige crear una herramienta propia. Frida puede responderla mediante el prototipo implementado, aunque con mayor trabajo específico de arquitectura y con más limitaciones que TracerPIN.

## 8. Qué observamos

En el control `known` esperábamos estas 12 escrituras:

```text
offset 0x00: 11
offset 0x01: 22
offset 0x04: AABBCCDD
offsets 0x08–0x0F: 08 09 0A 0B 0C 0D 0E 0F
offset 0x08: 99
```

TracerPIN recuperó esas 12 escrituras y sus valores. Con la extensión
`-interior 1 -interior-size 64`, también las recuperó usando el buffer normal
con guardias. Valgrind y DynamoRIO
mostraron 14 escrituras en sus trazas sin filtrar: las 12 de `known_writes()`
y dos escrituras posteriores del allocator durante `free()`. Como en el modo
directo `compressed == allocation`, los metadatos de liberación caen al
comienzo del mismo bloque seleccionado. Por lo tanto, esas dos escrituras no
pertenecen a la secuencia de la biblioteca bajo estudio. El prototipo de Frida con
`Stalker` también recuperó las 12 escrituras y sus bytes. Valgrind y DynamoRIO
estándar recuperaron las operaciones, direcciones y tamaños, pero no los
valores.

En el caso zlib, todos los programas terminaron correctamente: zlib produjo
334 bytes comprimidos. TracerPIN registró valores asociados con sus 17
escrituras seleccionadas. Con `-interior 1 -interior-size 8192`, la nueva
versión registró 352 eventos, incluyendo 17 escrituras sobre el destino y una
escritura de la variable puntero. El prototipo de Frida registró 16 eventos sobre el
buffer —13 lecturas y 3 escrituras— junto con sus bytes observados. Valgrind y
DynamoRIO estándar registraron accesos detallados, pero no el contenido de
cada escritura. `MemoryAccessMonitor` de Frida produjo solamente callbacks de
página; no debe confundirse con la variante basada en `Stalker`.

## 9. ¿Las herramientas obtendrían los mismos valores?

No automáticamente. Para comparar valores de forma justa habría que definir un formato común:

```text
orden | operación | dirección | tamaño | bytes | instrucción | hilo
```

Después habría que adaptar Valgrind para registrar valores y adaptar el ejemplo
`memval` de DynamoRIO para el mismo formato. Frida ya tiene una primera
implementación experimental, pero debe endurecerse antes de considerarla un
trazador general.

También habría que normalizar diferencias como escrituras vectoriales, instrucciones de cadenas, endianness y accesos divididos. Una herramienta puede registrar una escritura vectorial de 32 bytes como un evento y otra dividirla en varios eventos. La comparación debe considerar dirección, tamaño y bytes, no solamente el número de eventos.

## 10. Conclusión

| Necesidad | Herramienta más adecuada |
| --- | --- |
| Saber rápidamente si una página fue tocada | Frida `MemoryAccessMonitor` |
| Obtener un listado general de lecturas/escrituras | Valgrind o DynamoRIO |
| Obtener PC, tamaño e hilo | DynamoRIO |
| Obtener valores escritos con poca instrumentación adicional | TracerPIN |
| Prototipar valores en tiempo de ejecución sin modificar zlib | Frida `Stalker` |
| Construir un trazador general de valores | DynamoRIO + `memval` como base |

Para la pregunta central de este caso, la recomendación provisional es usar
TracerPIN como referencia principal. Frida demostró que puede responderla con
`Stalker`, pero el resultado es un prototipo x86-64 con costo y cobertura que
deben evaluarse. DynamoRIO/`memval` sigue siendo la alternativa más adecuada
para construir un trazador mantenible y general. Valgrind sirve como baseline
detallado, pero no como solución de valores sin desarrollar una herramienta
propia.
