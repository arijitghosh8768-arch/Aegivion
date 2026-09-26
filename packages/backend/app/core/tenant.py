from fastapi import HTTPException, status

from app.repositories import OrganizationRepository


def get_current_organization(current_user, db):
    user_id = current_user.get("user_id") if isinstance(current_user, dict) else getattr(current_user, "id", None)
    
    # In some places current_user dict has id instead of user_id, let's be flexible
    if not user_id and isinstance(current_user, dict):
        user_id = current_user.get("id")

    organization_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user is required",
        )

    if not organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not associated with an organization",
        )

    org_repo = OrganizationRepository(db)

    membership = org_repo.get_membership(
        user_id=str(user_id),
        organization_id=str(organization_id),
    )

    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not a member of this organization",
        )

    return str(organization_id)
