"""Compatibility entrypoint for the complete non-production hosted pipeline."""
from rs9.hosted_contract import REQUIRED_RECEIPTS, REQUIRED_RECEIPT_FILES
from rs9.hosted_pipeline import main, run_lane
from rs9.hosted_summary import summarize

if __name__ == "__main__":
    raise SystemExit(main())
