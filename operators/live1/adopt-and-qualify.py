"""Manager-only entrypoint; source adoption, hosted results, then stop."""
from rs9.adopt_candidate import main

if __name__ == "__main__":
    raise SystemExit(main())
