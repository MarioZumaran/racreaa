# RACREAA

**Plataforma SaaS B2B Multi-Tenant de Auditoría Operativa**  
De La Mora Zumarán Kitchen Support

## Stack

- **Frontend**: HTML/CSS/JS (PWA-ready, Zero-Trust)
- **Backend**: Vercel Serverless Functions (Node.js ESM)
- **Base de datos**: PostgreSQL con Row-Level Security
- **Storage**: Vercel Blob (evidencia fotográfica)
- **Auth**: JWT HS256 + Refresh Token Rotation
- **Email**: Resend

## Estructura

```
racreaa/
├── api/
│   ├── auth/
│   │   ├── login.js       # JWT + bcrypt + rate limiting
│   │   ├── refresh.js     # RTR — Refresh Token Rotation
│   │   └── logout.js      # Revocación de sesión
│   └── submit-audit.js    # Endpoint principal de auditoría
├── frontend/
│   ├── login.html         # Pantalla de acceso multi-tenant
│   └── calificacion-alimentos.html
├── db/
│   ├── schema.sql                 # Schema principal + RLS + particionado
│   └── schema_auth_addendum.sql   # Tablas de autenticación
├── docs/
│   └── env.example        # Variables de entorno requeridas
├── vercel.json            # Configuración de despliegue + security headers
└── package.json
```

## Variables de entorno

Ver `docs/env.example` para la lista completa. Configurar en Vercel Dashboard > Settings > Environment Variables.

## Despliegue

```bash
npm install
npx vercel --prod
```

---

*Confidencial — De La Mora Zumarán Kitchen Support © 2026*

<!-- deploy: 2026-04-30T16:47:56Z -->
