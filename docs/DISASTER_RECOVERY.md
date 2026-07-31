# Aegivion Disaster Recovery Plan

## Database Backup Strategy
- **Frequency**: Daily automated SQL dumps at 2:00 AM UTC.
- **Retention**: 30 calendar days.
- **Location**: Encrypted storage bucket.
- **Backup Command**:
  ```bash
  pg_dump -U aegivion aegivion > backup_$(date +%Y%m%d).sql
  gzip backup_*.sql
  ```

## Restore Procedure
1. Stop API services:
   ```bash
   docker-compose down
   ```
2. Re-create clean database target:
   ```sql
   DROP DATABASE aegivion;
   CREATE DATABASE aegivion;
   ```
3. Decompress and restore schema:
   ```bash
   gunzip -c backup_xxxx.sql.gz | psql -U aegivion aegivion
   ```
4. Perform migrations check:
   ```bash
   alembic upgrade head
   ```
5. Restart services.
