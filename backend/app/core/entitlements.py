"""Account + entitlement dependencies for Pro-gated endpoints."""

from __future__ import annotations

from fastapi import Depends, HTTPException, status

from app.core.auth import CurrentUser, get_current_user
from app.db.account_store import Account, account_store


async def get_account(user: CurrentUser = Depends(get_current_user)) -> Account:
    return account_store.get(user.id)


async def require_pro(account: Account = Depends(get_account)) -> Account:
    if not account.is_pro:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="This feature requires the VMAXweb Pro plan.",
        )
    return account
