"""Entry point aplikasi CryptoVerify CLI."""

from __future__ import annotations

from pathlib import Path
import sys


def _ensure_project_root_on_path() -> None:
    """Memastikan root proyek berada di sys.path saat dijalankan langsung."""
    project_root = str(Path(__file__).resolve().parent)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)


def main() -> None:
    """Inisialisasi komponen MVC dan jalankan aplikasi CLI."""
    _ensure_project_root_on_path()
    from cli.controller import CLIController
    from cli.view import CLIView

    view = CLIView()
    controller = CLIController(view=view)
    controller.run()


if __name__ == "__main__":
    main()
