from django.contrib import admin
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.utils.html import format_html
from .models import User, TwoFactorAuth, DeviceRemembered, PasswordResetOTP


class CustomUserCreationForm(UserCreationForm):
    """Custom user creation form for admin"""
    class Meta:
        model = User
        fields = ('email', 'username', 'first_name', 'last_name')


class CustomUserChangeForm(UserChangeForm):
    """Custom user change form for admin"""
    class Meta:
        model = User
        fields = '__all__'


class TwoFactorAuthInline(admin.StackedInline):
    """Inline admin for 2FA settings"""
    model = TwoFactorAuth
    extra = 0
    readonly_fields = ('created_at', 'updated_at')
    
    def has_add_permission(self, request, obj=None):
        # Only one 2FA record per user
        if obj and hasattr(obj, 'two_factor'):
            return False
        return True


class DeviceRememberedInline(admin.TabularInline):
    """Inline admin for remembered devices"""
    model = DeviceRemembered
    extra = 0
    readonly_fields = ('created_at', 'expires_at', 'ip_address', 'user_agent')
    fields = (
        'device_name', 'device_id', 'ip_address', 'is_active', 
        'created_at', 'expires_at'
    )
    
    def has_add_permission(self, request, obj=None):
        return False  # Don't allow adding devices from admin


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom User admin"""
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm
    
    list_display = (
        'email', 'username', 'first_name', 'last_name', 
        'account_type', 'is_email_verified', 'has_2fa', 
        'is_active', 'is_staff', 'date_joined'
    )
    
    list_filter = (
        'is_active', 'is_staff', 'is_superuser', 'account_type', 
        'is_email_verified', 'country', 'date_joined'
    )
    
    search_fields = ('email', 'username', 'first_name', 'last_name')
    
    ordering = ('-date_joined',)
    
    readonly_fields = ('date_joined', 'last_login')
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('email', 'username', 'password')
        }),
        ('Personal Info', {
            'fields': ('first_name', 'last_name', 'phone')
        }),
        ('Location', {
            'fields': ('country', 'state')
        }),
        ('Account Settings', {
            'fields': (
                'account_type', 'is_email_verified', 'is_active', 
                'is_staff', 'is_superuser'
            )
        }),
        ('Permissions', {
            'fields': ('groups', 'user_permissions'),
            'classes': ('collapse',)
        }),
        ('Important Dates', {
            'fields': ('last_login', 'date_joined'),
            'classes': ('collapse',)
        }),
    )
    
    add_fieldsets = (
        ('Basic Information', {
            'classes': ('wide',),
            'fields': (
                'email', 'username', 'password1', 'password2',
                'first_name', 'last_name'
            ),
        }),
        ('Account Details', {
            'fields': ('country', 'state', 'account_type'),
        }),
    )
    
    inlines = [TwoFactorAuthInline, DeviceRememberedInline]
    
    def has_2fa(self, obj):
        """Check if user has 2FA enabled"""
        if hasattr(obj, 'two_factor'):
            return obj.two_factor.is_enabled
        return False
    has_2fa.boolean = True
    has_2fa.short_description = '2FA Enabled'
    
    def get_queryset(self, request):
        """Optimize queryset with related objects"""
        return super().get_queryset(request).select_related('two_factor')
    
    actions = [
        'verify_email', 'unverify_email', 'activate_users', 
        'deactivate_users', 'disable_2fa'
    ]
    
    def verify_email(self, request, queryset):
        """Mark selected users' emails as verified"""
        count = queryset.update(is_email_verified=True)
        self.message_user(
            request, 
            f'Successfully verified email for {count} users.'
        )
    verify_email.short_description = "Mark emails as verified"
    
    def unverify_email(self, request, queryset):
        """Mark selected users' emails as unverified"""
        count = queryset.update(is_email_verified=False)
        self.message_user(
            request, 
            f'Successfully unverified email for {count} users.'
        )
    unverify_email.short_description = "Mark emails as unverified"
    
    def activate_users(self, request, queryset):
        """Activate selected users"""
        count = queryset.update(is_active=True)
        self.message_user(
            request, 
            f'Successfully activated {count} users.'
        )
    activate_users.short_description = "Activate selected users"
    
    def deactivate_users(self, request, queryset):
        """Deactivate selected users"""
        count = queryset.update(is_active=False)
        self.message_user(
            request, 
            f'Successfully deactivated {count} users.'
        )
    deactivate_users.short_description = "Deactivate selected users"
    
    def disable_2fa(self, request, queryset):
        """Disable 2FA for selected users"""
        count = 0
        for user in queryset:
            if hasattr(user, 'two_factor'):
                user.two_factor.is_enabled = False
                user.two_factor.backup_codes = []
                user.two_factor.save()
                # Also remove TOTP devices
                from django_otp.plugins.otp_totp.models import TOTPDevice
                TOTPDevice.objects.filter(user=user).delete()
                count += 1
        
        self.message_user(
            request, 
            f'Successfully disabled 2FA for {count} users.'
        )
    disable_2fa.short_description = "Disable 2FA for selected users"


@admin.register(TwoFactorAuth)
class TwoFactorAuthAdmin(admin.ModelAdmin):
    """Admin for 2FA settings"""
    list_display = ('user', 'is_enabled', 'created_at', 'updated_at')
    list_filter = ('is_enabled', 'created_at')
    search_fields = ('user__email', 'user__username')
    readonly_fields = ('created_at', 'updated_at', 'backup_codes_count')
    
    fieldsets = (
        ('User', {
            'fields': ('user',)
        }),
        ('Settings', {
            'fields': ('is_enabled',)
        }),
        ('Backup Codes', {
            'fields': ('backup_codes_count',),
            'description': 'Number of backup codes generated'
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def backup_codes_count(self, obj):
        """Show number of backup codes"""
        return len(obj.backup_codes) if obj.backup_codes else 0
    backup_codes_count.short_description = 'Backup Codes Count'
    
    def get_queryset(self, request):
        """Optimize queryset"""
        return super().get_queryset(request).select_related('user')


@admin.register(DeviceRemembered)
class DeviceRememberedAdmin(admin.ModelAdmin):
    """Admin for remembered devices"""
    list_display = (
        'user', 'device_name_display', 'ip_address', 
        'is_active', 'is_expired', 'created_at'
    )
    list_filter = (
        'is_active', 'created_at', 'expires_at'
    )
    search_fields = (
        'user__email', 'user__username', 'device_name', 
        'ip_address', 'device_id'
    )
    readonly_fields = (
        'device_id', 'user_agent_display', 'created_at', 
        'expires_at', 'is_expired'
    )
    
    fieldsets = (
        ('Device Information', {
            'fields': (
                'user', 'device_name', 'device_id', 'ip_address'
            )
        }),
        ('Status', {
            'fields': ('is_active', 'is_expired')
        }),
        ('Details', {
            'fields': ('user_agent_display',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'expires_at'),
            'classes': ('collapse',)
        }),
    )
    
    def device_name_display(self, obj):
        """Display device name or default"""
        return obj.device_name or 'Unknown Device'
    device_name_display.short_description = 'Device Name'
    
    def user_agent_display(self, obj):
        """Display formatted user agent"""
        if obj.user_agent:
            return format_html(
                '<div style="max-width: 300px; word-wrap: break-word;">{}</div>',
                obj.user_agent
            )
        return 'N/A'
    user_agent_display.short_description = 'User Agent'
    
    def is_expired(self, obj):
        """Check if device is expired"""
        return obj.is_expired()
    is_expired.boolean = True
    is_expired.short_description = 'Expired'
    
    def get_queryset(self, request):
        """Optimize queryset"""
        return super().get_queryset(request).select_related('user')
    
    actions = ['deactivate_devices', 'activate_devices']
    
    def deactivate_devices(self, request, queryset):
        """Deactivate selected devices"""
        count = queryset.update(is_active=False)
        self.message_user(
            request, 
            f'Successfully deactivated {count} devices.'
        )
    deactivate_devices.short_description = "Deactivate selected devices"
    
    def activate_devices(self, request, queryset):
        """Activate selected devices"""
        count = queryset.update(is_active=True)
        self.message_user(
            request, 
            f'Successfully activated {count} devices.'
        )
    activate_devices.short_description = "Activate selected devices"


@admin.register(PasswordResetOTP)
class PasswordResetOTPAdmin(admin.ModelAdmin):

    """Admin for password reset OTP"""
    list_display = ('user', 'code', 'created_at', 'expires_at', 'used')
    list_filter = ('used', 'created_at')
    search_fields = ('user__email', 'user__username', 'code')
    readonly_fields = ('created_at', 'expires_at')
    
    fieldsets = (
        ('User Information', {
            'fields': ('user',)
        }),
        ('OTP Details', {
            'fields': ('code', 'used')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'expires_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        """Optimize queryset"""
        return super().get_queryset(request).select_related('user')

admin.site.site_header = 'BuildCalc Administration'
admin.site.site_title = 'BuildCalc Admin'
admin.site.index_title = 'Welcome to BuildCalc Administration'