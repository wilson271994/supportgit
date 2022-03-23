from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import AbstractUser
from rest_framework import serializers
from django.db import models


class MyUser(AbstractUser):
    phone = models.CharField("Telephone", max_length=128, blank=True, unique=True)
    USERNAME_FIELD = 'username'
    pass


class Package(models.Model):
    name = models.CharField("Nom du Package", max_length=32)
    price = models.IntegerField("Prix du Package")
    tag = models.CharField("Liste des Entreprises", max_length=196)
    active = models.BooleanField("Active?", default=True)
    timespan = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        db_table = "pack"

    pass


class PackageData(models.Model):
    name = models.CharField("Nom du Package", max_length=128)
    pack = models.ForeignKey(Package, on_delete=models.CASCADE, null=True, related_name='children')
    active = models.BooleanField("Active?", default=True)
    timespan = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        db_table = "packdata"

    pass


class PackageDataSerializer(serializers.ModelSerializer):
    class Meta:
        fields = "__all__"
        model = PackageData


class PackageSerializer(serializers.ModelSerializer):
    tag = serializers.SerializerMethodField()
    children_list = serializers.SerializerMethodField('_get_children')

    def _get_children(self, obj):
        serializer = PackageDataSerializer(PackageData.objects.filter(pack__id=obj.id), many=True)
        return serializer.data

    def get_tag(self, obj):
        return str(obj.tag).split(",")

    class Meta:
        fields = "__all__"
        model = Package

    pass


GATEWAY = (
    ("liyeplimal", "LiyePlimal"),
    ("limopay", "LimoPay")
)

STATUS = (
    ("P", "En Attente"),
    ("R", "Rejeté"),
    ("A", "Accepté")
)


class Abonnement(models.Model):
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE, related_name='subscriber')
    pack = models.ForeignKey(Package, on_delete=models.CASCADE, related_name='package')
    transaction = models.CharField("Transaction ID", max_length=256, blank=True)
    gateway = models.CharField("Gateway", max_length=32, choices=GATEWAY, default="liyeplimal")
    status = models.CharField("Statut", max_length=16, choices=STATUS, default="P")
    subdate = models.DateField("Date de subscription", auto_now_add=True)
    expdate = models.DateField("Date d'expiration", blank=True, null=True)
    active = models.BooleanField("Active?", default=False)

    def __str__(self):
        return self.user.username + " - " + self.pack.name

    class Meta:
        db_table = "subscription"

    pass


class AbonnementSerializer(serializers.ModelSerializer):
    pack = serializers.SerializerMethodField()

    def get_pack(self, obj):
        return obj.pack.name

    class Meta:
        fields = "__all__"
        model = Abonnement

    pass


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        fields = ("id", 'username', 'last_name', 'first_name', 'email', 'phone', 'is_active')
        model = MyUser
        read_only_fields = ('is_active', 'is_staff', 'date_joined', 'last_login')
        extra_kwargs = {
            'password': {'write_only': True}
        }

    pass
