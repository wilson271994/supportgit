# Generated by Django 3.2.7 on 2021-10-13 10:30

from django.conf import settings
import django.contrib.auth.models
import django.contrib.auth.validators
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='Package',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=32, verbose_name='Nom du Package')),
                ('price', models.IntegerField(verbose_name='Prix du Package')),
                ('tag', models.CharField(max_length=196, verbose_name='Liste des Entreprises')),
                ('active', models.BooleanField(default=True, verbose_name='Active?')),
                ('timespan', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'pack',
            },
        ),
        migrations.CreateModel(
            name='MyUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(error_messages={'unique': 'A user with that username already exists.'}, help_text='Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.', max_length=150, unique=True, validators=[django.contrib.auth.validators.UnicodeUsernameValidator()], verbose_name='username')),
                ('first_name', models.CharField(blank=True, max_length=150, verbose_name='first name')),
                ('last_name', models.CharField(blank=True, max_length=150, verbose_name='last name')),
                ('email', models.EmailField(blank=True, max_length=254, verbose_name='email address')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('phone', models.CharField(blank=True, max_length=128, verbose_name='Telephone')),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.Group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.Permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
                'abstract': False,
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='PackageData',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=128, verbose_name='Nom du Package')),
                ('active', models.BooleanField(default=True, verbose_name='Active?')),
                ('timespan', models.DateTimeField(auto_now_add=True)),
                ('pack', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='children', to='Abonnement.package')),
            ],
            options={
                'db_table': 'packdata',
            },
        ),
        migrations.CreateModel(
            name='Abonnement',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('transaction', models.CharField(blank=True, max_length=256, verbose_name='Transaction ID')),
                ('gateway', models.CharField(choices=[('liyeplimal', 'LiyePlimal'), ('limopay', 'LimoPay')], default='liyeplimal', max_length=32, verbose_name='Gateway')),
                ('status', models.CharField(choices=[('P', 'En Attente'), ('R', 'Rejet??'), ('A', 'Accept??')], default='P', max_length=16, verbose_name='Statut')),
                ('subdate', models.DateField(auto_now_add=True, verbose_name='Date de subscription')),
                ('expdate', models.DateField(blank=True, null=True, verbose_name="Date d'expiration")),
                ('active', models.BooleanField(default=False, verbose_name='Active?')),
                ('pack', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='package', to='Abonnement.package')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='subscriber', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'subscription',
            },
        ),
    ]
