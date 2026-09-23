import os
import pytest

# Ensure JWT_SECRET_KEY is set for all tests
os.environ["JWT_SECRET_KEY"] = "test_jwt_secret_key_12345"
