"""Administrator-only inspection of the local evidence chain."""
from fastapi import APIRouter, Depends, HTTPException, Query

from api.security import require_api_key, require_operator_key
from modules.evidence_audit.store import EvidenceStoreError, get_evidence_store

router = APIRouter(dependencies=[Depends(require_api_key)])


@router.get("/records", dependencies=[Depends(require_operator_key)])
async def list_evidence_records(limit: int = Query(100, ge=1, le=500)) -> dict:
    try:
        store = get_evidence_store()
        return {
            "schema": "auctaryn.evidence-page.v1",
            "integrity_mode": store.integrity_mode,
            "records": await store.list_records(limit),
        }
    except EvidenceStoreError as exc:
        raise HTTPException(status_code=503, detail="Evidence store unavailable") from exc


@router.get("/verify", dependencies=[Depends(require_operator_key)])
async def verify_evidence_chain() -> dict:
    try:
        return await get_evidence_store().verify()
    except EvidenceStoreError as exc:
        raise HTTPException(status_code=503, detail="Evidence verification unavailable") from exc
