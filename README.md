# PrimeLakeHouse Superset with Supabase JWT Authentication

## Multi-Tenant Superset Setup

This setup integrates Apache Superset with Supabase JWT authentication for multi-tenant role-based access control.

## Features

- ✅ JWT-based SSO using Supabase Auth
- ✅ Role mapping (Admin → Admin, Member → Alpha, Viewer → Gamma)
- ✅ Multi-tenant Row-Level Security (RLS) via `current_tenant()` Jinja macro
- ✅ Single Superset instance serving multiple tenants
- ✅ PostgreSQL as metadata database

## Setup

1. Copy `superset_config.py` to the same directory
2. Create `.env` file with your secrets
3. Run `docker-compose up -d`
4. Access Superset at `http://localhost:8088`

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SUPERSET_SECRET_KEY` | Superset secret key (change in production!) |
| `SUPABASE_JWT_SECRET` | Your Supabase JWT secret (from Project Settings → API) |
| `POSTGRES_PASSWORD` | PostgreSQL password for metadata DB |

## Supabase JWT Claims Required

Your Supabase JWT must contain:

```json
{
  "role": "admin",      // admin, member, or viewer
  "tenant_id": "tenant-uuid-123"
}
