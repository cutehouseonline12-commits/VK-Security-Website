# VK SECURITY

Full-stack security monitoring application with React/Vite PWA frontend, Express/WebSocket backend, Prisma/PostgreSQL, authenticated device pairing, WebRTC camera streaming, motion events, recordings and browser push notifications.

## Deployment
- Frontend: Netlify using `netlify.toml`.
- Backend: a long-lived Node service such as Render using `render.yaml`.
- Database: PostgreSQL/Neon.
- WebRTC: configure STUN and preferably TURN for cross-network use.
- Production recordings should use private object storage rather than ephemeral local disk.

## Local development
1. Configure `server/.env` from `server/.env.example`.
2. Run `npm install`, `npx prisma generate`, and `npx prisma migrate deploy` in `server`.
3. Run `npm run dev` in `server`.
4. Configure `client/.env` with `VITE_API_URL` and run `npm install && npm run dev` in `client`.

Camera access, push notifications and WebRTC require HTTPS in normal production browser environments. Mobile browsers may suspend camera execution when backgrounded or locked.
