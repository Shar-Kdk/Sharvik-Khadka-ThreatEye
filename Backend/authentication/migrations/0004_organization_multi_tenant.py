# Generated migration for multi-tenant structure
# This migration adds Organization model and updates User model

from django.db import migrations, models
import django.db.models.deletion


def migrate_existing_users(apps, schema_editor):
    """Data migration: Convert existing users to new role system
    
    Strategy:
    - Superusers/staff → Platform Owners (no organization)
    - Regular users → Create default organization and assign as Org Admins
    """
    User = apps.get_model('authentication', 'User')
    Organization = apps.get_model('authentication', 'Organization')
    
    # Create a default organization for existing regular users
    default_org, created = Organization.objects.get_or_create(
        name='Default Organization',
        defaults={
            'subscription_tier': 'free',
            'max_users': 100,
            'is_active': True
        }
    )
    
    # Migrate existing users
    for user in User.objects.all():
        if user.is_superuser or user.is_staff:
            # Convert superusers/staff to Platform Owners
            user.role = 'platform_owner'
            user.organization = None
        else:
            # Convert regular users to Org Admins in default organization
            user.role = 'org_admin'
            user.organization = default_org
        
        # Save without calling full_clean to avoid validation during migration
        user.save(update_fields=['role', 'organization'])


def reverse_migration(apps, schema_editor):
    """Reverse data migration (if rollback is needed)"""
    User = apps.get_model('authentication', 'User')
    
    # Restore is_staff for Platform Owners
    for user in User.objects.filter(role='platform_owner'):
        user.is_staff = True
        user.is_superuser = True
        user.save(update_fields=['is_staff', 'is_superuser'])


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0003_remove_user_email_sent'),
    ]

    operations = [
        # Create Organization model
        migrations.CreateModel(
            name='Organization',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='Organization name (must be unique)', max_length=255, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, help_text='Organization creation timestamp')),
                ('is_active', models.BooleanField(default=True, help_text='Whether organization subscription is active')),
                ('subscription_tier', models.CharField(
                    choices=[
                        ('free', 'Free Trial'),
                        ('basic', 'Basic'),
                        ('professional', 'Professional'),
                        ('enterprise', 'Enterprise')
                    ],
                    default='free',
                    help_text='Current subscription tier',
                    max_length=20
                )),
                ('max_users', models.IntegerField(default=5, help_text='Maximum number of users allowed in this organization')),
            ],
            options={
                'verbose_name': 'Organization',
                'verbose_name_plural': 'Organizations',
                'ordering': ['name'],
            },
        ),
        
        # Add role field to User
        migrations.AddField(
            model_name='user',
            name='role',
            field=models.CharField(
                choices=[
                    ('platform_owner', 'Platform Owner'),
                    ('org_admin', 'Organization Admin')
                ],
                default='org_admin',
                help_text="User's role in the system",
                max_length=20
            ),
        ),
        
        # Add organization field to User (nullable temporarily for migration)
        migrations.AddField(
            model_name='user',
            name='organization',
            field=models.ForeignKey(
                blank=True,
                help_text='Organization this user belongs to (null for Platform Owners)',
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='users',
                to='authentication.organization'
            ),
        ),
        
        # Run data migration
        migrations.RunPython(migrate_existing_users, reverse_migration),
    ]
