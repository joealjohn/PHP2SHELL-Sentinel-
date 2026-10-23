"""users, sessions, assets

Revision ID: a481839888c5
Revises: 
Create Date: 2026-10-23 18:43:09.784545

"""
from __future__ import annotations

import app.models
import sqlalchemy as sa
from alembic import op
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql

revision = 'a481839888c5'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('users',
    sa.Column('id', app.models.GUID(length=36), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('email_verified', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_table('assets',
    sa.Column('id', app.models.GUID(length=36), nullable=False),
    sa.Column('user_id', app.models.GUID(length=36), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('url', sa.String(length=2048), nullable=False),
    sa.Column('normalized_url', sa.String(length=2048), nullable=False),
    sa.Column('host', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('authorization_confirmed', sa.Boolean(), nullable=False),
    sa.Column('authorization_confirmed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('monitoring_enabled', sa.Boolean(), nullable=False),
    sa.Column('scan_interval_seconds', sa.Integer(), nullable=False),
    sa.Column('last_scan_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('next_scan_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_assets_host'), 'assets', ['host'], unique=False)
    op.create_index(op.f('ix_assets_user_id'), 'assets', ['user_id'], unique=False)
    op.create_table('notifications',
    sa.Column('id', app.models.GUID(length=36), nullable=False),
    sa.Column('user_id', app.models.GUID(length=36), nullable=False),
    sa.Column('type', sa.String(length=64), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('data', sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql'), nullable=True),
    sa.Column('read_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_notifications_user_id'), 'notifications', ['user_id'], unique=False)
    op.create_table('sessions',
    sa.Column('id', app.models.GUID(length=36), nullable=False),
    sa.Column('user_id', app.models.GUID(length=36), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('csrf_token', sa.String(length=64), nullable=False),
    sa.Column('ip_address', sa.String(length=64), nullable=True),
    sa.Column('user_agent', sa.String(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sessions_token_hash'), 'sessions', ['token_hash'], unique=True)
    op.create_index(op.f('ix_sessions_user_id'), 'sessions', ['user_id'], unique=False)
    op.create_table('audit_logs',
    sa.Column('id', app.models.GUID(length=36), nullable=False),
    sa.Column('user_id', app.models.GUID(length=36), nullable=True),
    sa.Column('asset_id', app.models.GUID(length=36), nullable=True),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('resource_type', sa.String(length=64), nullable=True),
    sa.Column('resource_id', sa.String(length=64), nullable=True),
    sa.Column('ip_address', sa.String(length=64), nullable=True),
    sa.Column('detail', sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql'), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_action'), 'audit_logs', ['action'], unique=False)
    op.create_index(op.f('ix_audit_logs_user_id'), 'audit_logs', ['user_id'], unique=False)
    op.create_table('disclosure_contacts',
    sa.Column('id', app.models.GUID(length=36), nullable=False),
    sa.Column('user_id', app.models.GUID(length=36), nullable=False),
    sa.Column('asset_id', app.models.GUID(length=36), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=True),
    sa.Column('contact_url', sa.String(length=2048), nullable=True),
    sa.Column('source', sa.String(length=64), nullable=False),
    sa.Column('source_url', sa.String(length=2048), nullable=True),
    sa.Column('confidence', sa.String(length=20), nullable=False),
    sa.Column('policy_url', sa.String(length=2048), nullable=True),
    sa.Column('encryption_url', sa.String(length=2048), nullable=True),
    sa.Column('preferred_languages', sa.String(length=120), nullable=True),
    sa.Column('mx_verified', sa.Boolean(), nullable=False),
    sa.Column('discovered_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_disclosure_contacts_asset_id'), 'disclosure_contacts', ['asset_id'], unique=False)
    op.create_index(op.f('ix_disclosure_contacts_user_id'), 'disclosure_contacts', ['user_id'], unique=False)
    op.create_table('scans',
    sa.Column('id', app.models.GUID(length=36), nullable=False),
    sa.Column('asset_id', app.models.GUID(length=36), nullable=False),
    sa.Column('user_id', app.models.GUID(length=36), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('scanner_version', sa.String(length=32), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('duration_seconds', sa.Float(), nullable=True),
    sa.Column('celery_task_id', sa.String(length=64), nullable=True),
    sa.Column('summary', sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql'), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('error_code', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scans_asset_id'), 'scans', ['asset_id'], unique=False)
    op.create_index(op.f('ix_scans_status'), 'scans', ['status'], unique=False)
    op.create_index(op.f('ix_scans_user_id'), 'scans', ['user_id'], unique=False)
    op.create_table('findings',
    sa.Column('id', app.models.GUID(length=36), nullable=False),
    sa.Column('asset_id', app.models.GUID(length=36), nullable=False),
    sa.Column('scan_id', app.models.GUID(length=36), nullable=True),
    sa.Column('user_id', app.models.GUID(length=36), nullable=False),
    sa.Column('vulnerability_id', sa.String(length=64), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('severity', sa.String(length=20), nullable=False),
    sa.Column('cvss', sa.Numeric(precision=4, scale=1), nullable=True),
    sa.Column('confidence', sa.String(length=20), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('state', sa.String(length=30), nullable=False),
    sa.Column('summary', sa.Text(), nullable=True),
    sa.Column('impact', sa.Text(), nullable=True),
    sa.Column('remediation', sa.Text(), nullable=True),
    sa.Column('detected_version', sa.String(length=32), nullable=True),
    sa.Column('fixed_version', sa.String(length=32), nullable=True),
    sa.Column('vendor_patch_possible', sa.Boolean(), nullable=False),
    sa.Column('detection_method', sa.String(length=64), nullable=True),
    sa.Column('scanner_version', sa.String(length=32), nullable=True),
    sa.Column('references', sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql'), nullable=True),
    sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_findings_asset_id'), 'findings', ['asset_id'], unique=False)
    op.create_index(op.f('ix_findings_severity'), 'findings', ['severity'], unique=False)
    op.create_index(op.f('ix_findings_state'), 'findings', ['state'], unique=False)
    op.create_index(op.f('ix_findings_status'), 'findings', ['status'], unique=False)
    op.create_index(op.f('ix_findings_user_id'), 'findings', ['user_id'], unique=False)
    op.create_index(op.f('ix_findings_vulnerability_id'), 'findings', ['vulnerability_id'], unique=False)
    op.create_table('disclosures',
    sa.Column('id', app.models.GUID(length=36), nullable=False),
    sa.Column('finding_id', app.models.GUID(length=36), nullable=False),
    sa.Column('contact_id', app.models.GUID(length=36), nullable=True),
    sa.Column('user_id', app.models.GUID(length=36), nullable=False),
    sa.Column('asset_id', app.models.GUID(length=36), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('delivery_status', sa.String(length=30), nullable=True),
    sa.Column('subject', sa.Text(), nullable=False),
    sa.Column('body', sa.Text(), nullable=False),
    sa.Column('recipient_email', sa.String(length=320), nullable=False),
    sa.Column('recipient_source', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('approved_by', app.models.GUID(length=36), nullable=True),
    sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_sent_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('character_set', sa.String(length=32), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['approved_by'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['contact_id'], ['disclosure_contacts.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_disclosures_asset_id'), 'disclosures', ['asset_id'], unique=False)
    op.create_index(op.f('ix_disclosures_finding_id'), 'disclosures', ['finding_id'], unique=False)
    op.create_index(op.f('ix_disclosures_status'), 'disclosures', ['status'], unique=False)
    op.create_index(op.f('ix_disclosures_user_id'), 'disclosures', ['user_id'], unique=False)
    op.create_table('evidence',
    sa.Column('id', app.models.GUID(length=36), nullable=False),
    sa.Column('finding_id', app.models.GUID(length=36), nullable=False),
    sa.Column('evidence_type', sa.String(length=64), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('value', sa.Text(), nullable=False),
    sa.Column('source', sa.String(length=120), nullable=True),
    sa.Column('confidence', sa.String(length=20), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_evidence_finding_id'), 'evidence', ['finding_id'], unique=False)
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_evidence_finding_id'), table_name='evidence')
    op.drop_table('evidence')
    op.drop_index(op.f('ix_disclosures_user_id'), table_name='disclosures')
    op.drop_index(op.f('ix_disclosures_status'), table_name='disclosures')
    op.drop_index(op.f('ix_disclosures_finding_id'), table_name='disclosures')
    op.drop_index(op.f('ix_disclosures_asset_id'), table_name='disclosures')
    op.drop_table('disclosures')
    op.drop_index(op.f('ix_findings_vulnerability_id'), table_name='findings')
    op.drop_index(op.f('ix_findings_user_id'), table_name='findings')
    op.drop_index(op.f('ix_findings_status'), table_name='findings')
    op.drop_index(op.f('ix_findings_state'), table_name='findings')
    op.drop_index(op.f('ix_findings_severity'), table_name='findings')
    op.drop_index(op.f('ix_findings_asset_id'), table_name='findings')
    op.drop_table('findings')
    op.drop_index(op.f('ix_scans_user_id'), table_name='scans')
    op.drop_index(op.f('ix_scans_status'), table_name='scans')
    op.drop_index(op.f('ix_scans_asset_id'), table_name='scans')
    op.drop_table('scans')
    op.drop_index(op.f('ix_disclosure_contacts_user_id'), table_name='disclosure_contacts')
    op.drop_index(op.f('ix_disclosure_contacts_asset_id'), table_name='disclosure_contacts')
    op.drop_table('disclosure_contacts')
    op.drop_index(op.f('ix_audit_logs_user_id'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_action'), table_name='audit_logs')
    op.drop_table('audit_logs')
    op.drop_index(op.f('ix_sessions_user_id'), table_name='sessions')
    op.drop_index(op.f('ix_sessions_token_hash'), table_name='sessions')
    op.drop_table('sessions')
    op.drop_index(op.f('ix_notifications_user_id'), table_name='notifications')
    op.drop_table('notifications')
    op.drop_index(op.f('ix_assets_user_id'), table_name='assets')
    op.drop_index(op.f('ix_assets_host'), table_name='assets')
    op.drop_table('assets')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
    # ### end Alembic commands ###
