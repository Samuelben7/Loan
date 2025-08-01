from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.auth.models import User
from django.utils.translation import gettext_lazy as _
from django.core.validators import RegexValidator
from decimal import Decimal, ROUND_HALF_UP
from django.utils import timezone
from datetime import timedelta

class CustomUserManager(BaseUserManager):
    def create_user(self, email=None, cpf=None, password=None, **extra_fields):
        if not email and not cpf:
            raise ValueError(_('O e-mail ou o CPF é obrigatório.'))

        if email:
            email = self.normalize_email(email)
        
        # Não é necessário adicionar o CPF em extra_fields, já que ele é um campo do modelo
        user = self.model(email=email, cpf=cpf, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email=None, cpf=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser deve ter is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser deve ter is_superuser=True.')

        # O superusuário também precisa de cpf, então é tratado da mesma forma
        return self.create_user(email=email, cpf=cpf, password=password, **extra_fields)




class CustomUser(AbstractBaseUser, PermissionsMixin):
    name = models.CharField(_('nome completo'), max_length=100, blank=True, null=True)  

    email = models.EmailField(_('e-mail'), unique=True)
    cpf = models.CharField(
        _('CPF'),
        max_length=11,
        unique=True,
        null=True,
        blank=True,
        validators=[RegexValidator(r'^\d{11}$', _('Digite um CPF válido.')))
    )
    is_active = models.BooleanField(_('ativo'), default=True)
    is_staff = models.BooleanField(_('é staff'), default=False)




    # Relacionamentos
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='customuser_groups',
        blank=True,
        help_text=_('The groups this user belongs to.'),
        verbose_name=_('groups')
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='customuser_user_permissions',
        blank=True,
        help_text=_('Specific permissions for this user.'),
        verbose_name=_('user permissions')
    )

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'  # Pode ser 'email' ou 'cpf', depende de qual campo será usado para login
    REQUIRED_FIELDS = ['cpf']  # CPF será exigido no cadastro, junto com o email

    def __str__(self):
        return self.email if self.email else self.cpf


class Contratante(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='contratantes')
    name = models.CharField(max_length=100)
    cpf = models.CharField(max_length=11, unique=True)
    email = models.EmailField(blank=True, null=True)
    phone = models.CharField(max_length=20)
    city = models.TextField()
    neighborhood = models.TextField()
    road = models.TextField()
    number = models.IntegerField()



    def __str__(self):
        return f"{self.name} - {self.cpf}"


class ContratoEmprestimo(models.Model):
    contratante = models.ForeignKey(Contratante, on_delete=models.CASCADE, related_name='emprestimos')
    data_contrato = models.DateField(auto_now_add=True)
    valor_total = models.DecimalField(max_digits=10, decimal_places=2)
    numero_parcelas = models.PositiveIntegerField()
    juros_percentual = models.DecimalField(max_digits=5, decimal_places=2)
    observacoes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Empréstimo {self.id} - {self.contratante.nome}"

    def valor_total_com_juros(self):
        juros_decimal = self.juros_percentual / Decimal(100)
        return (self.valor_total * (1 + juros_decimal)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    def valor_parcela(self):
        if self.numero_parcelas == 0:
            return Decimal("0.00")
        total = self.valor_total_com_juros()
        return (total / self.numero_parcelas).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    def save(self, *args, **kwargs):
        is_new = self.pk is None
        super().save(*args, **kwargs)
        
        if is_new:
            valor = self.valor_parcela()
            data_base = timezone.now().date()

            parcelas = []
            for i in range(1, self.numero_parcelas + 1):
                data_vencimento = data_base + timedelta(days=30 * i)
                parcela = Parcela(
                    contrato=self,
                    numero=i,
                    valor=valor,
                    data_vencimento=data_vencimento,
                    paga=False
                )
                parcelas.append(parcela)
            Parcela.objects.bulk_create(parcelas)

    def parcelas_pagas(self):
        return self.parcelas.filter(paga=True).count()

    def parcelas_pendentes(self):
        return self.parcelas.filter(paga=False).count()



class Parcela(models.Model):
    contrato = models.ForeignKey(ContratoEmprestimo, on_delete=models.CASCADE, related_name='parcelas')
    numero = models.PositiveIntegerField(default=0)  # ex: 1, 2, 3...
    valor = models.DecimalField(max_digits=10, decimal_places=2)
    data_vencimento = models.DateField()
    paga = models.BooleanField(default=False)
    data_pagamento = models.DateField(blank=True, null=True)

    def __str__(self):
        return f"Parcela {self.numero} - Contrato {self.contrato.id}"
