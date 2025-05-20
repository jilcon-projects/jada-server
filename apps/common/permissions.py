"""
Custom permission classes for BuildCalc
"""

from rest_framework import permissions
from django.contrib.auth.models import AnonymousUser


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """
    
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to the owner
        return obj.owner == request.user


class IsOwnerOrStaff(permissions.BasePermission):
    """
    Permission that allows access to owners or staff users
    """
    
    def has_object_permission(self, request, view, obj):
        # Staff users have full access
        if request.user.is_staff:
            return True
        
        # Owners have full access
        return hasattr(obj, 'owner') and obj.owner == request.user


class IsCreatorOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow creators to edit their content
    """
    
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to the creator
        return hasattr(obj, 'created_by') and obj.created_by == request.user


class IsActiveUser(permissions.BasePermission):
    """
    Permission that only allows access to active users
    """
    
    def has_permission(self, request, view):
        return bool(request.user and 
                   request.user.is_authenticated and 
                   request.user.is_active)


class IsEmailVerified(permissions.BasePermission):
    """
    Permission that requires email verification
    """
    
    def has_permission(self, request, view):
        return bool(request.user and 
                   request.user.is_authenticated and 
                   hasattr(request.user, 'is_email_verified') and
                   request.user.is_email_verified)


class IsBusinessAccount(permissions.BasePermission):
    """
    Permission that only allows business accounts
    """
    
    def has_permission(self, request, view):
        return bool(request.user and 
                   request.user.is_authenticated and 
                   hasattr(request.user, 'account_type') and
                   request.user.account_type == 'business')


class CanModifyObject(permissions.BasePermission):
    """
    Permission that checks if user can modify an object based on various criteria
    """
    
    def has_object_permission(self, request, view, obj):
        # Read permissions for authenticated users
        if request.method in permissions.SAFE_METHODS:
            return request.user.is_authenticated
        
        # Admin users can modify anything
        if request.user.is_staff or request.user.is_superuser:
            return True
        
        # Owner can modify
        if hasattr(obj, 'owner') and obj.owner == request.user:
            return True
        
        # Creator can modify
        if hasattr(obj, 'created_by') and obj.created_by == request.user:
            return True
        
        # Check for assigned user
        if hasattr(obj, 'assigned_to') and obj.assigned_to == request.user:
            return True
        
        return False


class HasProjectAccess(permissions.BasePermission):
    """
    Permission that checks if user has access to a project
    """
    
    def has_object_permission(self, request, view, obj):
        # Get the project from the object
        project = obj if hasattr(obj, 'owner') else getattr(obj, 'project', None)
        
        if not project:
            return False
        
        # Project owner has full access
        if project.owner == request.user:
            return True
        
        # Assigned user has access
        if project.assigned_to == request.user:
            return True
        
        # Check collaborators
        if hasattr(project, 'collaborators'):
            return project.collaborators.filter(user=request.user).exists()
        
        return False


class IsCollaboratorOrOwner(permissions.BasePermission):
    """
    Permission for project collaborators
    """
    
    def has_permission(self, request, view):
        return request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        # Get project
        project = obj if hasattr(obj, 'collaborators') else getattr(obj, 'project', None)
        
        if not project:
            return False
        
        # Owner has full access
        if project.owner == request.user:
            return True
        
        # Check collaborator permission levels
        collaborator = project.collaborators.filter(user=request.user).first()
        
        if not collaborator:
            return False
        
        # Read-only operations
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write operations based on role
        if collaborator.role in ['editor', 'admin']:
            return True
        
        # Delete operations only for admin
        if view.action == 'destroy':
            return collaborator.role == 'admin'
        
        return False


class IsSameUserOrAdmin(permissions.BasePermission):
    """
    Permission that allows users to access only their own data or admins
    """
    
    def has_object_permission(self, request, view, obj):
        # Admin can access anything
        if request.user.is_staff or request.user.is_superuser:
            return True
        
        # Users can only access their own data
        user_field = getattr(obj, 'user', getattr(obj, 'owner', None))
        return user_field == request.user


class CanViewReports(permissions.BasePermission):
    """
    Permission for viewing reports
    """
    
    def has_object_permission(self, request, view, obj):
        # Creator can view
        if obj.created_by == request.user:
            return True
        
        # Check if report is shared with user
        if hasattr(obj, 'shares'):
            return obj.shares.filter(
                shared_with=request.user,
                is_active=True
            ).exists()
        
        # Project access
        if hasattr(obj, 'project'):
            return HasProjectAccess().has_object_permission(request, view, obj.project)
        
        return False


class CanDownloadReports(permissions.BasePermission):
    """
    Permission for downloading reports
    """
    
    def has_object_permission(self, request, view, obj):
        # Creator can download
        if obj.created_by == request.user:
            return True
        
        # Check share permissions
        if hasattr(obj, 'shares'):
            share = obj.shares.filter(
                shared_with=request.user,
                is_active=True
            ).first()
            
            if share:
                return share.can_download
        
        return False


class RateLimitPermission(permissions.BasePermission):
    """
    Permission that implements basic rate limiting
    """
    
    def has_permission(self, request, view):
        # This is a basic implementation
        # In production, you might want to use django-ratelimit or similar
        return True


class MaintenanceModePermission(permissions.BasePermission):
    """
    Permission that blocks access during maintenance mode
    """
    
    def has_permission(self, request, view):
        # Check if maintenance mode is enabled
        from django.conf import settings
        
        if getattr(settings, 'MAINTENANCE_MODE', False):
            # Allow staff to access during maintenance
            return request.user.is_staff
        
        return True