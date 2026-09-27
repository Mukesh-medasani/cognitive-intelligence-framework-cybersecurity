"""Launch CIF directly from the source checkout without installing packages."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / "src"))

from cif.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
