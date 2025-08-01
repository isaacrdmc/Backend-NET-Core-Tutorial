# AuthAPI




## Para crear un usuario
Se tiene que enviar un JSON como este:
``
{
  "emailAddress": "user@example.com",
  "fullName": "Isaac",
  "password": "Root1234!",
  "roles": ["User"]
}

``

Importante que la contraseña sea valida:
* Una mayusucula
* Letras de la 'a' a la 'z'
* Números
* Y un caracter especial

---
## Obtener el token
Acceder con las credenciaels validas para obtener el token.

---
## Enviar el token
Se copia el token y se lo envia con la palabra prebia "Bearer " junto con el espacio, seguido va el token obtenido y ya se pudo acceder.


(Todo esto es en esecnai la autenticación para provarla con swagger.)


