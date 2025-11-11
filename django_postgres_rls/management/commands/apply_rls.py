"""
Management command to apply RLS policies to registered models.

This command can be used to:
1. List all models registered for RLS
2. Apply RLS policies to specific apps or all registered models
3. Verify that grants were created correctly
"""

from django.core.management.base import BaseCommand, CommandError
from django.apps import apps
from django.db import connection

from django_postgres_rls import (
    get_registered_models,
    apply_rls_policies,
    setup_rls_for_app,
)


class Command(BaseCommand):
    help = 'Apply RLS policies to registered models and verify grants'

    def add_arguments(self, parser):
        parser.add_argument(
            '--list',
            action='store_true',
            help='List all registered RLS models',
        )
        parser.add_argument(
            '--app',
            type=str,
            help='Apply RLS policies only for models in this app',
        )
        parser.add_argument(
            '--verify',
            action='store_true',
            help='Verify that grants were created for roles',
        )
        parser.add_argument(
            '--show-grants',
            type=str,
            metavar='TABLE',
            help='Show all grants for a specific table',
        )

    def handle(self, *args, **options):
        verbosity = options['verbosity']

        # List registered models
        if options['list']:
            self.list_registered_models(verbosity)
            return

        # Show grants for a specific table
        if options['show_grants']:
            self.show_table_grants(options['show_grants'], verbosity)
            return

        # Apply RLS for specific app
        if options['app']:
            self.apply_for_app(options['app'], verbosity, options['verify'])
            return

        # Apply RLS for all registered models
        self.apply_for_all(verbosity, options['verify'])

    def list_registered_models(self, verbosity):
        """List all registered RLS models."""
        models = get_registered_models()

        if not models:
            self.stdout.write(self.style.WARNING(
                'No models are registered for RLS policy application.'
            ))
            self.stdout.write(
                'Models that inherit from RLSModel should be automatically registered.'
            )
            return

        self.stdout.write(self.style.SUCCESS(
            f'Found {len(models)} registered RLS model(s):\n'
        ))

        for model in models:
            policies = model.get_rls_policies()
            self.stdout.write(f'  • {model._meta.app_label}.{model.__name__}')
            self.stdout.write(f'    Table: {model._meta.db_table}')
            self.stdout.write(f'    Policies: {len(policies)}')

            if verbosity >= 2:
                for idx, policy in enumerate(policies):
                    role = policy.role_name or 'PUBLIC'
                    self.stdout.write(f'      [{idx}] {role}: {policy.command}')

            self.stdout.write('')

    def apply_for_app(self, app_label, verbosity, verify):
        """Apply RLS policies for all models in an app."""
        try:
            app_config = apps.get_app_config(app_label)
        except LookupError:
            raise CommandError(f"App '{app_label}' not found")

        self.stdout.write(self.style.SUCCESS(
            f"Applying RLS policies for app '{app_label}'...\n"
        ))

        setup_rls_for_app(app_label, verbosity=verbosity)

        if verify:
            self.verify_grants_for_app(app_label, verbosity)

    def apply_for_all(self, verbosity, verify):
        """Apply RLS policies for all registered models."""
        models = get_registered_models()

        if not models:
            self.stdout.write(self.style.WARNING(
                'No models registered for RLS policy application.'
            ))
            return

        self.stdout.write(self.style.SUCCESS(
            f'Applying RLS policies for {len(models)} model(s)...\n'
        ))

        for model in models:
            model_name = f"{model._meta.app_label}.{model.__name__}"

            try:
                policies = model.get_rls_policies()
                if not policies:
                    if verbosity >= 1:
                        self.stdout.write(
                            f'  {model_name}: No policies defined, skipping'
                        )
                    continue

                created, skipped = apply_rls_policies(model, verbosity=verbosity)

                if verbosity >= 1:
                    self.stdout.write(self.style.SUCCESS(
                        f'  ✓ {model_name}: {created} policies created, {skipped} skipped'
                    ))

                if verify:
                    self.verify_model_grants(model, verbosity)

            except Exception as e:
                self.stdout.write(self.style.ERROR(
                    f'  ✗ {model_name}: Error - {e}'
                ))
                if verbosity >= 2:
                    import traceback
                    traceback.print_exc()

    def verify_grants_for_app(self, app_label, verbosity):
        """Verify grants for all models in an app."""
        models = get_registered_models()
        app_models = [m for m in models if m._meta.app_label == app_label]

        if not app_models:
            return

        self.stdout.write(self.style.SUCCESS('\nVerifying grants...\n'))

        for model in app_models:
            self.verify_model_grants(model, verbosity)

    def verify_model_grants(self, model, verbosity):
        """Verify grants for a specific model."""
        table_name = model._meta.db_table
        policies = model.get_rls_policies()

        # Collect expected roles
        roles = set()
        for policy in policies:
            if policy.role_name:
                roles.add(policy.role_name)

        if not roles:
            return

        # Query grants for this table
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT grantee, privilege_type
                FROM information_schema.role_table_grants
                WHERE table_name = %s
                ORDER BY grantee, privilege_type
            """, [table_name])
            grants = cursor.fetchall()

        # Group grants by role
        grants_by_role = {}
        for grantee, privilege in grants:
            if grantee not in grants_by_role:
                grants_by_role[grantee] = []
            grants_by_role[grantee].append(privilege)

        # Check each expected role
        for role in roles:
            if role in grants_by_role:
                privs = ', '.join(sorted(grants_by_role[role]))
                self.stdout.write(self.style.SUCCESS(
                    f'    ✓ {role} → {table_name}: {privs}'
                ))
            else:
                self.stdout.write(self.style.ERROR(
                    f'    ✗ {role} → {table_name}: NO GRANTS FOUND'
                ))

    def show_table_grants(self, table_name, verbosity):
        """Show all grants for a specific table."""
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT grantee, privilege_type, is_grantable
                FROM information_schema.role_table_grants
                WHERE table_name = %s
                ORDER BY grantee, privilege_type
            """, [table_name])
            grants = cursor.fetchall()

        if not grants:
            self.stdout.write(self.style.WARNING(
                f"No grants found for table '{table_name}'"
            ))
            return

        self.stdout.write(self.style.SUCCESS(
            f"Grants for table '{table_name}':\n"
        ))

        current_grantee = None
        for grantee, privilege, is_grantable in grants:
            if grantee != current_grantee:
                if current_grantee is not None:
                    self.stdout.write('')
                self.stdout.write(f'  {grantee}:')
                current_grantee = grantee

            grantable = ' (grantable)' if is_grantable == 'YES' else ''
            self.stdout.write(f'    • {privilege}{grantable}')
