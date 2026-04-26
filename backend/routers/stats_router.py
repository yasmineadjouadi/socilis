from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from database.models import User, ScanHistory
from services.auth_service import get_current_user, get_db
from typing import Optional
from datetime import date

router = APIRouter()


@router.get("/")
def get_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    date_from: Optional[date] = Query(None, description="Filtrer depuis cette date (ex: 2024-01-01)"),
    date_to: Optional[date] = Query(None, description="Filtrer jusqu'à cette date (ex: 2024-12-31)"),
    ioc_type: Optional[str] = Query(None, description="Filtrer par type : hash, ip, domain, url, mail"),
):
    base = db.query(ScanHistory).filter(ScanHistory.user_id == current_user.id)

    # Appliquer les filtres
    if date_from:
        base = base.filter(ScanHistory.created_at >= date_from)
    if date_to:
        base = base.filter(ScanHistory.created_at <= date_to)
    if ioc_type:
        base = base.filter(ScanHistory.ioc_type == ioc_type)

    total = base.count()

    by_type = (
        base.with_entities(ScanHistory.ioc_type, func.count(ScanHistory.id))
        .group_by(ScanHistory.ioc_type)
        .all()
    )

    by_verdict = (
        base.with_entities(ScanHistory.final_verdict, func.count(ScanHistory.id))
        .group_by(ScanHistory.final_verdict)
        .all()
    )

    avg_score = (
        base.with_entities(func.avg(ScanHistory.risk_score))
        .scalar()
    )

    recent = (
        base.order_by(ScanHistory.created_at.desc())
        .limit(5)
        .all()
    )

    favorites_count = base.filter(ScanHistory.is_favorite == True).count()

    return {
        "filters_applied": {
            "date_from": str(date_from) if date_from else None,
            "date_to": str(date_to) if date_to else None,
            "ioc_type": ioc_type or None,
        },
        "total_scans": total,
        "favorites": favorites_count,
        "avg_risk_score": round(float(avg_score), 2) if avg_score else 0,
        "by_type": {t: c for t, c in by_type},
        "by_verdict": {v: c for v, c in by_verdict},
        "recent_scans": [
            {
                "id": s.id,
                "indicator": s.indicator,
                "ioc_type": s.ioc_type,
                "final_verdict": s.final_verdict,
                "risk_score": s.risk_score,
                "created_at": str(s.created_at),
            }
            for s in recent
        ]
    }