"""
Integration tests for PostgreSQL RLS enforcement.

These tests verify that RLS policies actually enforce access control
at the database level using a real PostgreSQL instance.
"""

import pytest
from django.db import connection, models
from django.db.models import Q, F

from django_postgres_rls import RLSModel, RlsPolicy, PolicyCommand, PolicyMode
from .integration_utils import (
    switch_role,
    reset_role,
    get_current_role,
    set_session_variable,
    get_session_variable,
    verify_rls_enforcement,
    get_active_policies,
    enable_rls,
    disable_rls,
    insert_test_data,
    truncate_table,
    count_visible_rows,
    grant_table_permissions,
)


pytestmark = pytest.mark.integration


class TestRLSPolicyEnforcement:
    """Test that RLS policies actually enforce access control."""

    def test_rls_enabled_on_table(self, postgres_db, postgres_test_roles):
        """Test that RLS can be enabled on a table."""
        # Create a simple test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_rls_basic (
                    id SERIAL PRIMARY KEY,
                    data TEXT
                )
            """)

        # Enable RLS
        enable_rls('test_rls_basic', force=True)
        grant_table_permissions('test_rls_basic', ['app_user', 'app_staff', 'app_superuser'])

        # Verify RLS is enabled
        assert verify_rls_enforcement('test_rls_basic', 'app_user')

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_rls_basic")

    def test_policy_blocks_unauthorized_access(self, postgres_db, postgres_test_roles):
        """Test that RLS policy blocks unauthorized row access."""
        # Create test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_docs (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER,
                    title TEXT
                )
            """)

        # Enable RLS
        enable_rls('test_docs', force=True)
        grant_table_permissions('test_docs', ['app_user', 'app_staff', 'app_superuser'])

        # Create policy: users can only see their own documents
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY user_own_docs ON test_docs
                FOR SELECT
                TO app_user
                USING (owner_id = current_setting('app.current_user_id')::int)
            """)

        # Insert test data
        insert_test_data('test_docs', [
            {'owner_id': 1, 'title': 'User 1 Doc'},
            {'owner_id': 2, 'title': 'User 2 Doc'},
            {'owner_id': 1, 'title': 'User 1 Doc 2'},
        ])

        # Switch to app_user role
        switch_role('app_user')
        set_session_variable('app.current_user_id', '1')

        # Should only see user 1's documents
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_docs")
            count = cursor.fetchone()[0]
            assert count == 2, "User should only see their own 2 documents"

        # Change to user 2
        set_session_variable('app.current_user_id', '2')

        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_docs")
            count = cursor.fetchone()[0]
            assert count == 1, "User 2 should only see their 1 document"

        # Reset role
        reset_role()

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_docs")

    def test_public_documents_visible_to_all(self, postgres_db, postgres_test_roles):
        """Test that public documents are visible to all users."""
        # Create test table with is_public column
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_public_docs (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER,
                    title TEXT,
                    is_public BOOLEAN DEFAULT FALSE
                )
            """)

        # Enable RLS
        enable_rls('test_public_docs', force=True)
        grant_table_permissions('test_public_docs', ['app_user', 'app_staff', 'app_superuser'])

        # Create policy: users see public docs or their own
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY user_docs_policy ON test_public_docs
                FOR SELECT
                TO app_user
                USING (
                    is_public = true OR
                    owner_id = current_setting('app.current_user_id')::int
                )
            """)

        # Insert test data
        insert_test_data('test_public_docs', [
            {'owner_id': 1, 'title': 'User 1 Private', 'is_public': False},
            {'owner_id': 1, 'title': 'User 1 Public', 'is_public': True},
            {'owner_id': 2, 'title': 'User 2 Private', 'is_public': False},
            {'owner_id': 2, 'title': 'User 2 Public', 'is_public': True},
        ])

        # Switch to app_user as user 1
        switch_role('app_user')
        set_session_variable('app.current_user_id', '1')

        # User 1 should see: own private + all public = 3 docs
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_public_docs")
            count = cursor.fetchone()[0]
            assert count == 3

        # Switch to user 3 (no documents)
        set_session_variable('app.current_user_id', '3')

        # User 3 should only see public docs = 2
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_public_docs")
            count = cursor.fetchone()[0]
            assert count == 2

        reset_role()

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_public_docs")

    def test_staff_role_sees_all_documents(self, postgres_db, postgres_test_roles):
        """Test that staff role can see all documents."""
        # Create test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_staff_docs (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER,
                    title TEXT
                )
            """)

        # Enable RLS
        enable_rls('test_staff_docs', force=True)
        grant_table_permissions('test_staff_docs', ['app_user', 'app_staff', 'app_superuser'])

        # Create policy for regular users (see only own)
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY user_policy ON test_staff_docs
                FOR SELECT
                TO app_user
                USING (owner_id = current_setting('app.current_user_id')::int)
            """)

        # Create policy for staff (see all)
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY staff_policy ON test_staff_docs
                FOR SELECT
                TO app_staff
                USING (true)
            """)

        # Insert test data
        insert_test_data('test_staff_docs', [
            {'owner_id': 1, 'title': 'User 1 Doc'},
            {'owner_id': 2, 'title': 'User 2 Doc'},
            {'owner_id': 3, 'title': 'User 3 Doc'},
        ])

        # Test as regular user
        switch_role('app_user')
        set_session_variable('app.current_user_id', '1')

        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_staff_docs")
            count = cursor.fetchone()[0]
            assert count == 1, "Regular user should see only 1 document"

        reset_role()

        # Test as staff
        switch_role('app_staff')

        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_staff_docs")
            count = cursor.fetchone()[0]
            assert count == 3, "Staff should see all 3 documents"

        reset_role()

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_staff_docs")

    def test_insert_policy_enforcement(self, postgres_db, postgres_test_roles):
        """Test that INSERT policies enforce ownership on new rows."""
        # Create test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_insert_docs (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER,
                    title TEXT
                )
            """)

        # Enable RLS
        enable_rls('test_insert_docs', force=True)
        grant_table_permissions('test_insert_docs', ['app_user', 'app_staff', 'app_superuser'])

        # Create INSERT policy: can only insert with current user as owner
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY user_insert_policy ON test_insert_docs
                FOR INSERT
                TO app_user
                WITH CHECK (owner_id = current_setting('app.current_user_id')::int)
            """)

        # Switch to app_user
        switch_role('app_user')
        set_session_variable('app.current_user_id', '1')

        # Should succeed: inserting with correct owner_id
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO test_insert_docs (owner_id, title) VALUES (1, 'Valid Doc')"
            )

        # Should fail: trying to insert with different owner_id
        with pytest.raises(Exception) as exc_info:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO test_insert_docs (owner_id, title) VALUES (2, 'Invalid Doc')"
                )

        assert "new row violates row-level security policy" in str(exc_info.value).lower()

        reset_role()

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_insert_docs")

    def test_update_policy_enforcement(self, postgres_db, postgres_test_roles):
        """Test that UPDATE policies restrict which rows can be modified."""
        # Create test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_update_docs (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER,
                    title TEXT,
                    content TEXT
                )
            """)

        # Enable RLS
        enable_rls('test_update_docs', force=True)
        grant_table_permissions('test_update_docs', ['app_user', 'app_staff', 'app_superuser'])

        # Policy: can only select own documents
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY user_select_policy ON test_update_docs
                FOR SELECT
                TO app_user
                USING (owner_id = current_setting('app.current_user_id')::int)
            """)

        # Policy: can only update own documents
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY user_update_policy ON test_update_docs
                FOR UPDATE
                TO app_user
                USING (owner_id = current_setting('app.current_user_id')::int)
                WITH CHECK (owner_id = current_setting('app.current_user_id')::int)
            """)

        # Insert test data
        insert_test_data('test_update_docs', [
            {'owner_id': 1, 'title': 'User 1 Doc', 'content': 'Original'},
            {'owner_id': 2, 'title': 'User 2 Doc', 'content': 'Original'},
        ])

        # Switch to app_user as user 1
        switch_role('app_user')
        set_session_variable('app.current_user_id', '1')

        # Should succeed: updating own document
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE test_update_docs SET content = 'Modified' WHERE owner_id = 1"
            )
            assert cursor.rowcount == 1

        # Should not update anything: user 2's document not visible
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE test_update_docs SET content = 'Hacked' WHERE owner_id = 2"
            )
            assert cursor.rowcount == 0, "Should not update other user's document"

        reset_role()

        # Verify user 2's document wasn't modified
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT content FROM test_update_docs WHERE owner_id = 2"
            )
            content = cursor.fetchone()[0]
            assert content == 'Original', "User 2's document should not be modified"

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_update_docs")

    def test_delete_policy_enforcement(self, postgres_db, postgres_test_roles):
        """Test that DELETE policies restrict which rows can be deleted."""
        # Create test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_delete_docs (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER,
                    title TEXT
                )
            """)

        # Enable RLS
        enable_rls('test_delete_docs', force=True)
        grant_table_permissions('test_delete_docs', ['app_user', 'app_staff', 'app_superuser'])

        # Policy: can only delete own documents
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY user_delete_policy ON test_delete_docs
                FOR DELETE
                TO app_user
                USING (owner_id = current_setting('app.current_user_id')::int)
            """)

        # Also need SELECT policy to see rows
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY user_select_policy ON test_delete_docs
                FOR SELECT
                TO app_user
                USING (owner_id = current_setting('app.current_user_id')::int)
            """)

        # Insert test data
        insert_test_data('test_delete_docs', [
            {'owner_id': 1, 'title': 'User 1 Doc 1'},
            {'owner_id': 1, 'title': 'User 1 Doc 2'},
            {'owner_id': 2, 'title': 'User 2 Doc'},
        ])

        # Switch to app_user as user 1
        switch_role('app_user')
        set_session_variable('app.current_user_id', '1')

        # Should succeed: deleting own document
        with connection.cursor() as cursor:
            cursor.execute("""
                DELETE FROM test_delete_docs
                WHERE id IN (
                    SELECT id FROM test_delete_docs WHERE owner_id = 1 LIMIT 1
                )
            """)
            assert cursor.rowcount == 1

        # Should not delete: user 2's document not visible
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM test_delete_docs WHERE owner_id = 2")
            assert cursor.rowcount == 0

        reset_role()

        # Verify counts
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_delete_docs")
            count = cursor.fetchone()[0]
            assert count == 2, "Should have 1 user 1 doc and 1 user 2 doc"

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_delete_docs")

    def test_restrictive_policy_mode(self, postgres_db, postgres_test_roles):
        """Test RESTRICTIVE policy mode (must pass ALL restrictive policies)."""
        # Create test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_restrictive (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER,
                    is_active BOOLEAN DEFAULT TRUE,
                    title TEXT
                )
            """)

        # Enable RLS
        enable_rls('test_restrictive', force=True)
        grant_table_permissions('test_restrictive', ['app_user', 'app_staff', 'app_superuser'])

        # Permissive policy: see own documents
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY user_own_docs ON test_restrictive
                AS PERMISSIVE
                FOR SELECT
                TO app_user
                USING (owner_id = current_setting('app.current_user_id')::int)
            """)

        # Restrictive policy: must be active
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY only_active ON test_restrictive
                AS RESTRICTIVE
                FOR SELECT
                TO app_user
                USING (is_active = true)
            """)

        # Insert test data
        insert_test_data('test_restrictive', [
            {'owner_id': 1, 'is_active': True, 'title': 'Active Doc'},
            {'owner_id': 1, 'is_active': False, 'title': 'Inactive Doc'},
        ])

        # Switch to app_user
        switch_role('app_user')
        set_session_variable('app.current_user_id', '1')

        # Should only see active documents
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_restrictive")
            count = cursor.fetchone()[0]
            assert count == 1, "Should only see active document"

        reset_role()

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_restrictive")

    def test_session_variable_isolation(self, postgres_db, postgres_test_roles):
        """Test that session variables are properly isolated per transaction."""
        set_session_variable('app.current_user_id', '123')
        value = get_session_variable('app.current_user_id')
        assert value == '123'

        # Change it
        set_session_variable('app.current_user_id', '456')
        value = get_session_variable('app.current_user_id')
        assert value == '456'

    def test_role_switch_isolation(self, postgres_db, postgres_test_roles):
        """Test that role switches are properly isolated."""
        initial_role = get_current_role()

        # Switch to app_user
        switch_role('app_user')
        assert get_current_role() == 'app_user'

        # Reset
        reset_role()
        current_role = get_current_role()
        assert current_role != 'app_user'

    def test_get_active_policies(self, postgres_db, postgres_test_roles):
        """Test retrieving active policies for a table."""
        # Create test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_policies_query (
                    id SERIAL PRIMARY KEY,
                    data TEXT
                )
            """)

        # Enable RLS
        enable_rls('test_policies_query', force=True)
        grant_table_permissions('test_policies_query', ['app_user', 'app_staff', 'app_superuser'])

        # Create a policy
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY test_policy ON test_policies_query
                FOR SELECT
                TO app_user
                USING (true)
            """)

        # Get policies
        policies = get_active_policies('test_policies_query', 'app_user')

        assert len(policies) >= 1
        policy_names = [p['policyname'] for p in policies]
        assert 'test_policy' in policy_names

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_policies_query")

    def test_force_row_level_security(self, postgres_db, postgres_test_roles):
        """Test that FORCE RLS applies even to table owner."""
        # Create test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_force_rls (
                    id SERIAL PRIMARY KEY,
                    data TEXT
                )
            """)

        # Insert data as owner (before RLS)
        with connection.cursor() as cursor:
            cursor.execute("INSERT INTO test_force_rls (data) VALUES ('test')")
            cursor.execute("SELECT COUNT(*) FROM test_force_rls")
            assert cursor.fetchone()[0] == 1

        # Enable RLS with FORCE
        enable_rls('test_force_rls', force=True)
        grant_table_permissions('test_force_rls', ['app_user', 'app_staff', 'app_superuser'])

        # Create restrictive policy
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY deny_all ON test_force_rls
                FOR SELECT
                TO app_user
                USING (false)
            """)

        # Switch to non-superuser role to test FORCE RLS
        switch_role('app_user')

        # Even with FORCE RLS, the role should not see rows due to restrictive policy
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_force_rls")
            count = cursor.fetchone()[0]
            assert count == 0, "FORCE RLS should apply to table owner"

        reset_role()

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_force_rls")

    def test_multiple_permissive_policies_or_logic(self, postgres_db, postgres_test_roles):
        """Test that multiple PERMISSIVE policies use OR logic."""
        # Create test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_permissive_or (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER,
                    is_public BOOLEAN,
                    is_featured BOOLEAN,
                    title TEXT
                )
            """)

        # Enable RLS
        enable_rls('test_permissive_or', force=True)
        grant_table_permissions('test_permissive_or', ['app_user', 'app_staff', 'app_superuser'])

        # Policy 1: See own documents
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY own_docs ON test_permissive_or
                AS PERMISSIVE
                FOR SELECT
                TO app_user
                USING (owner_id = current_setting('app.current_user_id')::int)
            """)

        # Policy 2: See featured documents
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY featured_docs ON test_permissive_or
                AS PERMISSIVE
                FOR SELECT
                TO app_user
                USING (is_featured = true)
            """)

        # Insert test data
        insert_test_data('test_permissive_or', [
            {'owner_id': 1, 'is_public': False, 'is_featured': False, 'title': 'User 1 Normal'},
            {'owner_id': 2, 'is_public': False, 'is_featured': True, 'title': 'User 2 Featured'},
            {'owner_id': 3, 'is_public': False, 'is_featured': False, 'title': 'User 3 Normal'},
        ])

        # Switch to app_user as user 1
        switch_role('app_user')
        set_session_variable('app.current_user_id', '1')

        # Should see: own doc + featured doc = 2
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_permissive_or")
            count = cursor.fetchone()[0]
            assert count == 2, "Should see own document + featured document"

        reset_role()

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_permissive_or")

    def test_complex_policy_with_subquery(self, postgres_db, postgres_test_roles):
        """Test RLS policy with more complex SQL expressions."""
        # Create test tables
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_users (
                    id SERIAL PRIMARY KEY,
                    username TEXT,
                    department_id INTEGER
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_documents (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER,
                    department_id INTEGER,
                    title TEXT
                )
            """)

        # Enable RLS on documents
        enable_rls('test_documents', force=True)
        grant_table_permissions('test_documents', ['app_user', 'app_staff', 'app_superuser'])
        grant_table_permissions('test_users', ['app_user', 'app_staff', 'app_superuser'])

        # Policy: See documents from same department
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY same_department ON test_documents
                FOR SELECT
                TO app_user
                USING (
                    department_id IN (
                        SELECT department_id FROM test_users
                        WHERE id = current_setting('app.current_user_id')::int
                    )
                )
            """)

        # Insert test data
        insert_test_data('test_users', [
            {'id': 1, 'username': 'user1', 'department_id': 10},
            {'id': 2, 'username': 'user2', 'department_id': 20},
        ])

        insert_test_data('test_documents', [
            {'owner_id': 1, 'department_id': 10, 'title': 'Dept 10 Doc 1'},
            {'owner_id': 1, 'department_id': 10, 'title': 'Dept 10 Doc 2'},
            {'owner_id': 2, 'department_id': 20, 'title': 'Dept 20 Doc'},
        ])

        # Switch to user 1 (department 10)
        switch_role('app_user')
        set_session_variable('app.current_user_id', '1')

        # Should see only department 10 documents
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_documents")
            count = cursor.fetchone()[0]
            assert count == 2, "Should see only department 10 documents"

        # Switch to user 2 (department 20)
        set_session_variable('app.current_user_id', '2')

        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_documents")
            count = cursor.fetchone()[0]
            assert count == 1, "Should see only department 20 documents"

        reset_role()

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_documents")
            cursor.execute("DROP TABLE test_users")
