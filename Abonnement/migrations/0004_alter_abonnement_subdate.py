# Generated by Django 3.2.7 on 2021-10-15 09:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Abonnement', '0003_alter_abonnement_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='abonnement',
            name='subdate',
            field=models.DateField(verbose_name='Date de subscription'),
        ),
    ]