from django.contrib import admin
from django.utils.translation import gettext, gettext_lazy as _
# Register your models here.
from django.contrib.auth.admin import UserAdmin

from .models import Package, Abonnement, PackageData, MyUser


class AbonnementAdmin(admin.ModelAdmin):
    list_display = ('user', 'pack', 'status', 'subdate', 'expdate', 'active')
    list_filter = ('user', 'pack', 'status', 'subdate', 'expdate', 'active')


class PackageAdmin(admin.ModelAdmin):
    list_display = ('name', 'price', 'active')


class PackageDataAdmin(admin.ModelAdmin):
    list_display = ('name', 'pack', 'active')


class MyUserAdmin(UserAdmin):
    fieldsets = (
        (None, {'fields': ('username', 'phone', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    list_display = ('username', 'email', 'first_name', 'last_name', 'phone', 'is_staff')


admin.site.register(PackageData, PackageDataAdmin)
admin.site.register(Package, PackageAdmin)
admin.site.register(MyUser, MyUserAdmin)
admin.site.register(Abonnement, AbonnementAdmin)
