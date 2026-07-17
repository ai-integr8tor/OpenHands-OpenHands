from __future__ import annotations

import logging
import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from openhands.app_server.app_lifespan.app_lifespan_service import AppLifespanService

logger = logging.getLogger(__name__)


class OssAppLifespanService(AppLifespanService):
    run_alembic_on_startup: bool = True

    async def __aenter__(self):
        if self.run_alembic_on_startup:
            self.run_alembic()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        pass

    def _get_sqlite_db_path(self) -> Path | None:
        """Return the SQLite database file path if SQLite is in use."""
        from openhands.app_server.config import get_global_config

        db_session = get_global_config().db_session
        if db_session.host:
            return None
        return db_session.persistence_dir / 'openhands.db'

    def _ensure_db_parent_dir(self, db_path: Path) -> None:
        """Ensure the parent directory exists and is readable/writable."""
        parent_dir = db_path.parent
        try:
            parent_dir.mkdir(parents=True, exist_ok=True, mode=0o775)
        except OSError as mkdir_err:
            logger.warning(
                'Could not create database parent directory %s: %s',
                parent_dir,
                mkdir_err,
            )
            return

        try:
            os.chmod(parent_dir, 0o775)
        except OSError as chmod_err:
            logger.warning(
                'Could not update permissions for %s: %s',
                parent_dir,
                chmod_err,
            )

    def _run_alembic_upgrade(self, alembic_cfg: Config) -> None:
        """Run the Alembic upgrade command."""
        command.upgrade(alembic_cfg, 'head')

    def run_alembic(self) -> None:
        # Run alembic upgrade head to ensure database is up to date
        alembic_dir = Path(__file__).parent / 'alembic'
        alembic_ini = alembic_dir / 'alembic.ini'

        # Create alembic config with absolute paths
        alembic_cfg = Config(str(alembic_ini))
        alembic_cfg.set_main_option('script_location', str(alembic_dir))

        # Change to alembic directory for the command execution
        original_cwd = os.getcwd()
        try:
            os.chdir(str(alembic_dir.parent))
            try:
                self._run_alembic_upgrade(alembic_cfg)
            except Exception as e:
                if not isinstance(e, (OperationalError, SQLAlchemyError)):
                    raise

                db_path = self._get_sqlite_db_path()
                if db_path is None:
                    raise

                logger.warning(
                    'Database migration failed for SQLite (%s: %s). '
                    'Removing the database file and retrying.',
                    type(e).__name__,
                    e,
                )

                if db_path.exists():
                    try:
                        db_path.unlink()
                    except OSError as unlink_err:
                        logger.error(
                            'Failed to remove SQLite database file %s: %s',
                            db_path,
                            unlink_err,
                        )
                        raise

                self._ensure_db_parent_dir(db_path)

                self._run_alembic_upgrade(alembic_cfg)
                logger.warning(
                    'SQLite database at %s was removed and migrations completed successfully.',
                    db_path,
                )
        finally:
            os.chdir(original_cwd)
