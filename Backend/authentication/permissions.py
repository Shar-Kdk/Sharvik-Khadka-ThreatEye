from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.db.models import Q


class IsPlatformOwner(permissions.BasePermission):
    
    message = "Only Platform Owners can access this resource."
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.is_platform_owner()
        )


class IsOrgAdmin(permissions.BasePermission):
    
    message = "Only Organization Admins can access this resource."
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.is_org_admin()
        )


class HasOrganizationAccess(permissions.BasePermission):
    
    message = "You do not have access to this organization."
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        if hasattr(obj, 'organization'):
            return request.user.has_organization_access(obj.organization)
        
        if obj.__class__.__name__ == 'Organization':
            return request.user.has_organization_access(obj)
        
        return False


class OrganizationAccessMixin:
    
    def get_queryset(self):
        queryset = super().get_queryset()
        user = self.request.user
        
        if user.is_platform_owner():
            return queryset
        
        if user.is_org_admin() and user.organization:
            if hasattr(queryset.model, 'organization'):
                return queryset.filter(organization=user.organization)
        
        return queryset.none()
    
    def check_organization_access(self, organization):
        if not self.request.user.has_organization_access(organization):
            raise PermissionDenied(
                "You do not have permission to access this organization."
            )


class PlatformOwnerRequiredMixin:
    
    permission_classes = [IsPlatformOwner]


def get_organization_queryset(user, queryset):
    if user.is_platform_owner():
        return queryset
    
    if user.is_org_admin() and user.organization:
        if hasattr(queryset.model, 'organization'):
            return queryset.filter(organization=user.organization)
    
    return queryset.none()


def get_user_organization(user):
    if user.is_platform_owner():
        return None
    
    if user.is_org_admin():
        if not user.organization:
            raise DjangoPermissionDenied(
                "Organization Admin must belong to an organization."
            )
        return user.organization
    
    raise DjangoPermissionDenied("Invalid user role.")


def require_organization_access(user, organization):
    if not user.has_organization_access(organization):
        raise DjangoPermissionDenied(
            f"You do not have access to organization: {organization.name}"
        )


class OrganizationQuerySet(models.QuerySet):
    
    def for_user(self, user):
        return get_organization_queryset(user, self)
    
    def for_organization(self, organization):
        return self.filter(organization=organization)


class OrganizationManager(models.Manager):
    
    def get_queryset(self):
        return OrganizationQuerySet(self.model, using=self._db)
    
    def for_user(self, user):
        return self.get_queryset().for_user(user)
    
    def for_organization(self, organization):
        return self.get_queryset().for_organization(organization)


from django.db import models
