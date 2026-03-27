
# Export SQLModel Base for Alembic to read metadata
# SQLModel already has the metadata inside its internal declarative base

# Import every model from every domain so they are registered in SQLModel.metadata
from src.users.models import User, UserBase  # noqa: F401
from src.tokens.models import PersonalAccessToken, TokenBase  # noqa: F401
from src.fraud.models import LoginAttempt, LoginAttemptBase  # noqa: F401
