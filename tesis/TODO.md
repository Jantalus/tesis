/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-
Probar, con PIN y Valgrind:

- Variable de memoria global
    - En una funcion llamada desde main: Variable local estatica (¿keyword static?)
- En una funcion llamada desde main: Variable local dinamica (malloc)

Que cosas me vendrian bien saber:
- Por arriba funcionamiento del motor de Valgrind (¿JIT? No creo)
- Por arriba funcionamiento del motor de PIN (JIT)
- Cosas comunes de C: Simbolos, donde viven las variables de memoria (malloc: heap) (estatico: stack)

/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-
DONDE VIVEN LAS VARIABLES

Segun el formato DWARF, y la data en este formato del ejecutable
compilado con flags de debu, para variables dentro de un scope de funcion:

- Variables dentro de una funcion
DW_AT_location    : 2 byte block: 91 50 	(DW_OP_fbreg: -48)
                    ^^^^^^^^^^^^^^^^^^^     ^^^^^^^^^^^^^^^^^
                    Cuanto ocupa            Offset dentro del stack
                                            cuando se evalue la funcion
- Variables globales
DW_AT_location    : 9 byte block: 3 30 40 0 0 0 0 0 0 	(DW_OP_addr: 4030)

- Variables que viven en el heap?
Probablemente se tenga el puntero en el stack. Y por lo tanto como el 
primer caso, que este en programaAlMomentoQueLlegaAFunc.Stack - offset

/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-
QUE HACER CON LA TOOL

Ahora o bien la tool provee parametrizacion para indicarle
desde cuando empezar a loggear, osea que cuando llegue a 
la funcion target empieze a loggear segun el offset de la variable.

O bien hay que modificar la tool para que pueda hacer esto :(
y por lo tanto entender PIN y toda la bola :(((

OBS: DWARF provee data de en que lugar de la memoria esta fisicamente
la funcion, osea puede ser una punta para filtrar.
/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-

dwarf_next_cu_header_d (cuando se tenga mas de una CompilingUnit)
dwarf_offdie_b (DIE Segun offset)
dwarf_die_offsets (recibe numero de atributo y te lo devuelve)
dwarf_diename (die name)
dwarf_attr 
dwarf_lowpc (die lowpc)
dwarf_highpc_b (die highpc)
dwarf_ELATRIBUTO (..)

/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-
OPTIONS DE LA TOOL ORIGINAL A TENER EN CUENTA

Comando para tracear sin logs de instrucciones, calls, bloques, y filtrando por rango de direcciones virtuales


Tracer -F 0x555555555139:0x5555555551bb -i 0 -b 0 -c 0 -o dwarfeame_filter.log -- prueba/dwarfeame 
(i)nstrucciones
(b)asic blocks
(c)alls
/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-
COMANDOS PARA COMPILADO Y LECTURA DE INFO DE DEBUG

Compilado:
g++ -O0 prueba/dynamic_vs_static/main.cpp -o prueba/read_dwarf_data -L/usr/local/lib -ldwarf

g++ -O0 prueba/dynamic_vs_static/main\ copy\ 2.cpp -g -o prueba/dwarfeame_vector -L/usr/local/lib -ldwarf

// Compilado; lectura de info de debug; traceo
g++ -O0 prueba/dynamic_vs_static/main\ copy\ 2.cpp -g -o prueba/dwarfeame_vector
readelf -wi prueba/dwarfeame_vector > readelf_vector_wi.txt
Tracer -o dwarfeame_vector.log -- prueba/dwarfeame_vector 

/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-
Queda pendiente el caso donde la funcion este distribuida en distintas regiones:
?La memoria virtual queda "contigua" ??


/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-
DETALLES PARA LA TOOL

- Agregar un LogTypeType para cuando este pulido


/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-
PODRIA PASAR QUE TENGA MAS DE UN OPERANDO PARA EL OFFSET??
