# Damasco App

Aplicación de gestión de pedidos para la cafetería Damasco. Backend en Node.js +
Express que sirve el frontend estático (`public/index.html`) y persiste el estado
de la app en una base de datos Postgres gratuita de [Neon](https://neon.tech),
desplegado gratis en [Render](https://render.com).

## Arquitectura

- **Frontend**: un único archivo `public/index.html` (HTML/CSS/JS), servido tal cual
  por Express. Guarda su estado llamando a `GET /api/state` y `POST /api/state`.
- **Backend**: `server.js`, Express + `pg` (node-postgres). Protegido con una
  contraseña compartida a nivel de servidor (independiente del PIN de camarero,
  que sigue viviendo en el frontend).
- **Base de datos**: una sola tabla `app_state` con una única fila (`id = 1`) que
  contiene todo el estado dinámico de la app como JSON.

## 1. Crear la base de datos en Neon

1. Entra en [neon.tech](https://neon.tech) y crea una cuenta gratuita.
2. Crea un nuevo proyecto (por ejemplo, `damasco`).
3. En el dashboard del proyecto, ve a **Connection Details** / **Dashboard**.
4. Selecciona el modo de conexión **Pooled connection** (el connection string debe
   incluir `-pooler` en el host, algo como
   `ep-xxxxx-pooler.eu-central-1.aws.neon.tech`). Es importante usar el pooled,
   no el directo: el plan free de Render "duerme" el servicio cuando no hay
   tráfico y al despertar necesita reconectar rápido sin agotar el límite de
   conexiones de Postgres.
5. Copia el connection string completo, con forma similar a:
   ```
   postgresql://usuario:password@ep-xxxxx-pooler.eu-central-1.aws.neon.tech/neondb?sslmode=require
   ```
6. Guárdalo — lo necesitarás como `DATABASE_URL` más abajo. No hace falta crear
   la tabla a mano: `server.js` ejecuta `CREATE TABLE IF NOT EXISTS` al arrancar.

## 2. Subir el proyecto a GitHub

```bash
git init
git add .
git commit -m "Damasco app: backend Express + Postgres (Neon)"
```

Crea un repositorio nuevo en GitHub y sube el código:

```bash
git remote add origin https://github.com/<tu-usuario>/damasco-app.git
git branch -M main
git push -u origin main
```

Verifica que `.env` **no** se haya subido (está en `.gitignore`).

## 3. Desplegar en Render

1. Entra en [render.com](https://render.com) y crea una cuenta gratuita.
2. Pulsa **New +** → **Web Service**.
3. Conecta tu cuenta de GitHub y selecciona el repositorio `damasco-app`.
   - Si el repo ya tiene `render.yaml`, Render detectará el blueprint
     automáticamente (**New +** → **Blueprint** también funciona).
4. Configuración del servicio:
   - **Runtime**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: Free
5. **No** actives ningún disco persistente y **no** añadas una base de datos de
   Render — la persistencia va a Neon.

### Variables de entorno en Render

En la sección **Environment** del servicio, añade:

| Variable         | Valor                                                              |
|------------------|---------------------------------------------------------------------|
| `DATABASE_URL`   | El connection string *pooled* copiado de Neon                      |
| `APP_PASSWORD`   | Una contraseña fuerte que compartirás con tu equipo                |
| `SESSION_SECRET` | Una cadena aleatoria larga (por ejemplo, generada con `openssl rand -hex 32`) |
| `NODE_ENV`       | `production` (ya viene definido en `render.yaml`)                  |

Nunca pongas estos valores en el código ni en el repositorio: solo existen como
variables de entorno en Render (y en tu `.env` local, que está ignorado por git).

6. Pulsa **Create Web Service**. Render instalará dependencias, arrancará
   `server.js` y te dará una URL pública `https://damasco-app-xxxx.onrender.com`
   con HTTPS automático.

## 4. Uso

1. Abre la URL de Render. Verás un formulario simple pidiendo la contraseña de
   servidor (`APP_PASSWORD`) — esta protección evita que cualquiera en internet
   acceda a la app.
2. Tras introducirla correctamente, se guarda una cookie de sesión firmada y se
   carga `public/index.html`, que a su vez muestra su propia pantalla de PIN
   para identificar al camarero/encargado (sin relación con la contraseña de
   servidor).
3. A partir de aquí, la app funciona igual que antes: creación de órdenes,
   ciclo Órdenes → Entregados → Pagadas, inventario, etc. — solo que ahora todo
   se guarda en Postgres (Neon) en vez de en memoria del navegador.

## 5. Ejecutar en local

Requiere Node.js 18+.

```bash
npm install
cp .env.example .env
# Edita .env con tu DATABASE_URL de Neon, y un APP_PASSWORD / SESSION_SECRET propios
npm start
```

La app quedará disponible en `http://localhost:3000`. En local, la cookie de
sesión no lleva el atributo `Secure` (el navegador la descartaría sin HTTPS);
en producción en Render, con `NODE_ENV=production`, sí se marca `Secure`.

## Seguridad

- La contraseña de servidor se compara con `crypto.timingSafeEqual` para evitar
  ataques de timing.
- La cookie de sesión es `httpOnly`, `SameSite=Strict` y (en producción) `Secure`,
  y va firmada con `SESSION_SECRET`.
- `helmet` añade cabeceras HTTP seguras por defecto.
- `express-rate-limit` limita `/api/login` y `/api/state` a ~60 peticiones por
  minuto por IP.
- Los payloads JSON están limitados a 2 MB.
- Todas las consultas a Postgres usan parámetros (`$1`, `$2`...); nunca se
  concatenan strings del usuario en SQL.
- Los errores internos (incluyendo los de Postgres) se registran en los logs
  del servidor pero nunca se devuelven al cliente; solo se responde con un
  mensaje genérico y el código HTTP adecuado.
- No hay CORS habilitado: frontend y backend viven en el mismo origen.
