---
title: Bulletproof OSINT - WWCTF 2024
time: 2024-12-07 24:00:00
categories: [CTF, WriteUps]
tags: [CTF, WriteUps, OSINT]
image: /assets/posts/Bulletproof/bulletproof.jpg
---

## Hola a todos!

Esta es la resolución del reto Bulletproof del WWCTF 2024.

Primero que todo nos dan la imagen que tenemos que investigar y tratar de encontrar en que dirección se encuentra.
![1](/assets/posts/Bulletproof/image1.jpg)
Realizar una busqueda inversa de la imagen lleva a una publicación de una compañía hablando sobre cristales blindados en estaciones de gasolina, aquí podemos llegar a la conclusión de que el local que estamos buscando es una de estas, probablemente de la compañía Shell ya que el esquema de colores que se ve en el cartel con el número "4" (rojo y amarillo) corresponde a esta compañía

Al observar de cerca algunos detalles en la foto se pueden ver en el cristal hay unas letras, al aplicar efecto espejo a la imagen para hacerlas legibles se ven una dirección y un número teléfonico que no se logran leer con total claridad

![2](/assets/posts/Bulletproof/image4.jpg)


De aquí se puede sacar un codigo zip (98405) que pertenece a Central Tacoma lo que reduce el área de búsqueda a esta zona

![3](/assets/posts/Bulletproof/image2.jpg)

Usando Google Maps se busca Shell Gas Station en esa zona y al observar los detalles de algunas de ellas podemos ver claramente que la dirección y el número teléfonico de una de ellas, corresponden con los antes encontrados en la imagen.

![4](/assets/posts/Bulletproof/image3.jpg)


`FLAG: wwf{3907s12thst_tacoma_wa98405_usa}`
