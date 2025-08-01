
from datetime import date, timedelta
from decimal import Decimal
import json
import os
import tempfile


from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator as token_generator
from django.core.mail import EmailMessage, send_mail
from django.db.models import Sum
from django.http import JsonResponse, HttpResponse, FileResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ValidationError

from django.contrib.auth.tokens import default_token_generator


from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView


from rest_framework_simplejwt.tokens import RefreshToken, AccessToken


from weasyprint import HTML


from .models import ContratoEmprestimo, Parcela


User = get_user_model()


from rest_framework.permissions import IsAuthenticated

class EstatisticasEmprestimosView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            hoje = timezone.now().date()

            # Contratos do usuário logado
            contratos_usuario = ContratoEmprestimo.objects.filter(contratante__user=user)

            def get_interval_data(model, field, filtro_adicional=None, valor_field=None):
                base = model.objects
                if model == ContratoEmprestimo:
                    base = base.filter(contratante__user=user)
                elif model == Parcela:
                    base = base.filter(contrato__contratante__user=user)

                if filtro_adicional:
                    base = base.filter(**filtro_adicional)

                valor_field = valor_field or ("valor_total" if model.__name__ == "ContratoEmprestimo" else "valor")
                return {
                    "mensal": base.filter(**{f"{field}__gte": hoje - timedelta(days=30)}).aggregate(soma=Sum(valor_field))["soma"] or 0,
                    "trimestral": base.filter(**{f"{field}__gte": hoje - timedelta(days=90)}).aggregate(soma=Sum(valor_field))["soma"] or 0,
                    "anual": base.filter(**{f"{field}__gte": hoje - timedelta(days=365)}).aggregate(soma=Sum(valor_field))["soma"] or 0,
                }

            # 1. Empréstimos concedidos
            emprestimos_totais = get_interval_data(ContratoEmprestimo, 'data_contrato')

            # 2. Valores pagos
            valores_pagos = get_interval_data(Parcela, 'data_pagamento', filtro_adicional={'paga': True})

            # 3. Total na rua sem juros
            total_emprestado_sem_juros = contratos_usuario.aggregate(
                total=Sum('valor_total')
            )['total'] or Decimal('0.00')

            total_pago_sem_juros = Decimal('0.00')
            for contrato in contratos_usuario:
                parcelas_pagas = contrato.parcelas.filter(paga=True).count()
                if contrato.numero_parcelas > 0:
                    porcentagem_paga = Decimal(parcelas_pagas) / Decimal(contrato.numero_parcelas)
                    valor_pago = porcentagem_paga * contrato.valor_total
                    total_pago_sem_juros += valor_pago

            total_na_rua_sem_juros = total_emprestado_sem_juros - total_pago_sem_juros

            # 4. Total na rua com juros
            total_com_juros = sum(
                [c.valor_total_com_juros() for c in contratos_usuario],
                Decimal('0.00')
            )
            total_parcelas_pagas = Parcela.objects.filter(
                contrato__contratante__user=user, paga=True
            ).aggregate(total=Sum('valor'))['total'] or Decimal('0.00')

            total_na_rua_com_juros = total_com_juros - total_parcelas_pagas

            # 5. Total de contratos existentes
            total_contratos = contratos_usuario.count()

            # 6. Previsão de lucro
            previsao_lucro = total_com_juros - total_emprestado_sem_juros

            # 7. Parcelas em atraso
            total_atrasos = Parcela.objects.filter(
                contrato__contratante__user=user,
                paga=False,
                data_vencimento__lt=hoje
            ).count()

            return Response({
                "emprestimos_totais": emprestimos_totais,
                "valores_pagos": valores_pagos,
                "total_na_rua_sem_juros": round(total_na_rua_sem_juros, 2),
                "total_na_rua_com_juros": round(total_na_rua_com_juros, 2),
                "total_contratos": total_contratos,
                "previsao_lucro_total": round(previsao_lucro, 2),
                "total_atrasos": total_atrasos
            })

        except Exception as e:
            return Response({"erro": str(e)}, status=500)


class EstatisticaMensalView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        mes_str = request.GET.get("mes")

        if not mes_str:
            return Response({"erro": "Parâmetro 'mes' é obrigatório."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            mes = int(mes_str)
            if mes < 1 or mes > 12:
                return Response({"erro": "O mês deve estar entre 1 e 12."}, status=status.HTTP_400_BAD_REQUEST)

            ano = timezone.now().year
            hoje = timezone.now().date()

            data_inicio = date(ano, mes, 1)
            data_fim = date(ano + 1, 1, 1) if mes == 12 else date(ano, mes + 1, 1)


            parcelas = Parcela.objects.filter(
                contrato__contratante__user=request.user,
                data_vencimento__gte=data_inicio,
                data_vencimento__lt=data_fim
            )

            total_pagas = parcelas.filter(paga=True).count()
            total_atrasadas = parcelas.filter(paga=False, data_vencimento__lt=hoje).count()
            total_a_vencer = parcelas.filter(paga=False, data_vencimento__gte=hoje).count()

            return Response({
                "pagas": total_pagas,
                "atrasadas": total_atrasadas,
                "a_vencer": total_a_vencer
            }, status=status.HTTP_200_OK)

        except ValueError:
            return Response({"erro": "O parâmetro 'mes' deve ser um número inteiro."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"erro": f"Erro interno: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            
            
@csrf_exempt
@login_required  # just users on 
def gerar_pdf_enviar_email(request, contrato_id):
    try:
        
        contrato = ContratoEmprestimo.objects.select_related('contratante').prefetch_related('parcelas').get(
            id=contrato_id,
            contratante__user=request.user
        )
        parcelas = contrato.parcelas.all().order_by('numero')

        dados = {
            'contrato': contrato,
            'contratante': contrato.contratante,
            'parcelas': parcelas,
            'valor_total_com_juros': contrato.valor_total_com_juros(),
            'valor_parcela': contrato.valor_parcela(),
        }

        html_string = render_to_string('past/contrato.html', dados)

        
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        temp_file.close()  
        HTML(string=html_string).write_pdf(target=temp_file.name)

       
        with open(temp_file.name, 'rb') as f:
            pdf_content = f.read()

        # here we are sending the email 
        email = EmailMessage(
            subject=f"Contrato de Empréstimo - {contrato.contratante.name}",
            body="Segue em anexo o contrato de empréstimo.",
            to=[contrato.contratante.email],
        )
        email.attach(f"Contrato_{contrato.contratante.name}.pdf", pdf_content, 'application/pdf')
        email.send()

        # Return the response here 
        response = FileResponse(open(temp_file.name, 'rb'), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="Contrato_{contrato.contratante.name}.pdf"'

        return response

    except ContratoEmprestimo.DoesNotExist:
        return HttpResponse("Contrato não encontrado ou você não tem permissão para acessá-lo.", status=404)

    except Exception as e:
        return HttpResponse(f"Erro ao gerar PDF: {str(e)}", status=500)

    finally:
        # remove temp file
        if 'temp_file' in locals() and os.path.exists(temp_file.name):
            os.remove(temp_file.name)


class RegisterView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        cpf = request.data.get('cpf')
        name = request.data.get('name') 

        # Verificar se e-mail e senha estão presentes
        if not email or not password:
            return Response({'error': 'E-mail e senha são obrigatórios.'}, status=status.HTTP_400_BAD_REQUEST)

        # Verificar se o e-mail já está cadastrado
        if User.objects.filter(email=email).exists():
            return Response({'error': 'E-mail já cadastrado. Faça login.'}, status=status.HTTP_400_BAD_REQUEST)

       
        user = User.objects.create_user(
            email=email, 
            cpf=cpf, 
            password=password, 
            name=name,
            is_active=False
        )
        # Gerar o UID para enviar por e-mail
        uid = urlsafe_base64_encode(str(user.pk).encode('utf-8'))  
        token = token_generator.make_token(user)  # Usando o token padrão do Django

        # Enviar o e-mail de ativação
        current_site = get_current_site(request)
        mail_subject = 'Ative sua conta no MyDriver'
        message = render_to_string('account/activation_email.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': uid,
            'token': token,
        })

        # Criando e configurando o e-mail com tipo HTML
        email_message = EmailMessage(
            subject=mail_subject,
            body=message,
            from_email='tami.hta1208@gmail.com',
            to=[email]
        )

        # Definindo o tipo de conteúdo como HTML
        email_message.content_subtype = "html"  # Garantindo que o conteúdo é tratado como HTML
        email_message.send()

        return Response({'message': 'Usuário registrado com sucesso. Verifique seu e-mail para ativar a conta.'}, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')  # Pode ser email ou CPF
        password = request.data.get('password')

        if not username or not password:
            return Response({'error': 'E-mail, CPF e senha são obrigatórios.'}, status=status.HTTP_400_BAD_REQUEST)

        # Usando o modelo de usuário customizado
        user_model = get_user_model()  # Aqui pegamos o modelo de usuário customizado
        user = None
        
        # Tenta localizar o usuário pelo e-mail ou CPF
        if '@' in username:  # Verifica se o "username" é um e-mail
            try:
                user = user_model.objects.get(email=username)
            except user_model.DoesNotExist:
                pass
        else:  # Caso contrário, tenta encontrar pelo CPF
            try:
                user = user_model.objects.get(cpf=username)
            except user_model.DoesNotExist:
                pass

        # Se não encontrar o usuário
        if not user:
            return Response({'error': 'Usuário não encontrado.'}, status=status.HTTP_404_NOT_FOUND)

        # Verifica se o usuário está ativo (se ele clicou no link de ativação)
        if not user.is_active:
            return Response({'error': 'Sua conta não foi ativada. Verifique seu e-mail para ativar.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Verifica se a senha está correta
        if not user.check_password(password):
            return Response({'error': 'Credenciais inválidas.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Gera os tokens JWT (access e refresh)
        refresh = RefreshToken.for_user(user)

        

        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'message': 'Logout realizado com sucesso.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': 'Erro ao realizar logout.'}, status=status.HTTP_400_BAD_REQUEST)



class ActivateAccountView(View):
    template_name = 'account/account_activated.html'
    template_error = 'account/account_activation_invalid.html'

    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode('utf-8')
            user = get_user_model().objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            user = None

        if user is not None and token_generator.check_token(user, token):
            user.is_active = True
            user.save()

            # Aqui pode enviar o e-mail se quiser
            current_site = get_current_site(request)
            mail_subject = 'Sua conta foi ativada!'
            message = render_to_string('account/account_activated_email.html', {
                'user': user,
                'domain': current_site.domain,
            })
            email_message = EmailMessage(
                subject=mail_subject,
                body=message,
                from_email='no-reply@mydriver.com',
                to=[user.email]
            )
            email_message.content_subtype = 'html'
            email_message.send()

            return render(request, self.template_name, {'user': user})

        else:
            return render(request, self.template_error)



class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({'error': 'E-mail é obrigatório.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = get_user_model().objects.get(email=email)
        except get_user_model().DoesNotExist:
            return Response({'error': 'Usuário não encontrado.'}, status=status.HTTP_404_NOT_FOUND)

        # Gerar UID e token para redefinição
        uid = urlsafe_base64_encode(str(user.pk).encode('utf-8'))  # Codifica o ID do usuário
        token = token_generator.make_token(user)

        # Gerar o link de redefinição de senha
        current_site = get_current_site(request)
       

        reset_link = f"http://{current_site.domain}/api/reset-password/{uid}/{token}/"

        # Enviar e-mail com o link para redefinir a senha
        mail_subject = 'Redefinir sua senha - MyDriver'

        # Renderizando o conteúdo HTML do e-mail com o link de redefinição
        message = render_to_string('account/password_reset_email.html', {
            'user': user,
            'reset_link': reset_link,
        })

        # Criando o e-mail com HTML
        email_message = EmailMessage(
            subject=mail_subject,
            body=message,
            from_email='Tami.hta1208@gmail.com',
            to=[email]
        )

        # Definir o tipo de conteúdo como HTML
        email_message.content_subtype = 'html'

        # Enviar o e-mail
        email_message.send()

        return Response({'message': 'E-mail de redefinição de senha enviado!'}, status=status.HTTP_200_OK)


class ResetPasswordPageView(View):
    template_name = 'account/reset_password.html'

    def get(self, request, uidb64, token):
        context = {'uidb64': uidb64, 'token': token}
        return render(request, self.template_name, context)

    def post(self, request, uidb64, token):
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if not new_password or not confirm_password:
            return render(request, self.template_name, {
                'error': 'Por favor, preencha os dois campos.',
                'uidb64': uidb64,
                'token': token
            })

        if new_password != confirm_password:
            return render(request, self.template_name, {
                'error': 'As senhas não coincidem.',
                'uidb64': uidb64,
                'token': token
            })

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = get_user_model().objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            return render(request, self.template_name, {'error': 'Usuário inválido.'})

        if not default_token_generator.check_token(user, token):
            return render(request, self.template_name, {'error': 'Token inválido ou expirado.'})

        try:
            validate_password(new_password, user)
        except ValidationError as e:
            return render(request, self.template_name, {
                'error': e.messages,
                'uidb64': uidb64,
                'token': token
            })

        user.set_password(new_password)
        user.save()

        return render(request, self.template_name, {'success': 'Senha redefinida com sucesso! Você já pode fazer login no App.'})

