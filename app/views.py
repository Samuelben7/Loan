from django.shortcuts import render
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.password_validation import validate_password
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.conf import settings
from rest_framework import status

from django.core.mail import EmailMessage
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator as token_generator
from django.http import HttpResponse
from django.template.loader import render_to_string
from weasyprint import HTML
import tempfile
from .models import ContratoEmprestimo
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.views.decorators.csrf import csrf_exempt
from weasyprint import HTML
import tempfile
from .models import ContratoEmprestimo
from django.http import FileResponse
import os
User = get_user_model()


@csrf_exempt
def gerar_pdf_enviar_email(request, contrato_id):
    try:
        contrato = ContratoEmprestimo.objects.select_related('contratante').prefetch_related('parcelas').get(id=contrato_id)
        parcelas = contrato.parcelas.all().order_by('numero')

        dados = {
            'contrato': contrato,
            'contratante': contrato.contratante,
            'parcelas': parcelas,
            'valor_total_com_juros': contrato.valor_total_com_juros(),
            'valor_parcela': contrato.valor_parcela(),
        }

        html_string = render_to_string('past/contrato.html', dados)

        # Criação do PDF temporário
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        temp_file.close()  # Fecha o ponteiro, WeasyPrint vai usar apenas o nome do arquivo
        HTML(string=html_string).write_pdf(target=temp_file.name)

        # Lê o conteúdo do PDF para o email
        with open(temp_file.name, 'rb') as f:
            pdf_content = f.read()

        # Envia e-mail com anexo
        email = EmailMessage(
            subject=f"Contrato de Empréstimo - {contrato.contratante.name}",
            body="Segue em anexo o contrato de empréstimo.",
            to=[contrato.contratante.email],
        )
        email.attach(f"Contrato_{contrato.contratante.name}.pdf", pdf_content, 'application/pdf')
        email.send()

        # Retorna o PDF como resposta HTTP
        response = FileResponse(open(temp_file.name, 'rb'), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="Contrato_{contrato.contratante.name}.pdf"'

        return response

    except ContratoEmprestimo.DoesNotExist:
        return HttpResponse("Contrato não encontrado.", status=404)

    except Exception as e:
        return HttpResponse(f"Erro ao gerar PDF: {str(e)}", status=500)

    finally:
        # Remove o arquivo temporário
        if 'temp_file' in locals() and os.path.exists(temp_file.name):
            os.remove(temp_file.name)


class RegisterView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        cpf = request.data.get('cpf')

        # Verificar se e-mail e senha estão presentes
        if not email or not password:
            return Response({'error': 'E-mail e senha são obrigatórios.'}, status=status.HTTP_400_BAD_REQUEST)

        # Verificar se o e-mail já está cadastrado
        if User.objects.filter(email=email).exists():
            return Response({'error': 'E-mail já cadastrado. Faça login.'}, status=status.HTTP_400_BAD_REQUEST)

        # Criar o usuário usando o manager do seu modelo personalizado
        user = User.objects.create_user(
            email=email, 
            cpf=cpf, 
            password=password, 
            is_active=False
        )
        # Gerar o UID para enviar por e-mail
        uid = urlsafe_base64_encode(str(user.pk).encode('utf-8'))  # Garantindo que o ID seja convertido para string antes de codificar
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

class ActivateAccountView(APIView):
    def get(self, request, uidb64, token):
        try:
            # Decodificar o uid a partir do uidb64
            uid = urlsafe_base64_decode(uidb64).decode('utf-8')
            user = get_user_model().objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            user = None

        # Verifica se o token é válido
        if user is not None and token_generator.check_token(user, token):
            # Ativar o usuário e salvar
            user.is_active = True
            user.save()
            
            # Enviar e-mail de confirmação de ativação
            current_site = get_current_site(request)
            mail_subject = 'Sua conta foi ativada!'
            message = render_to_string('account/account_activated_email.html', {
                'user': user,
                'domain': current_site.domain,
            })

            # Criar a mensagem de e-mail com a classe EmailMessage
            email_message = EmailMessage(
                subject=mail_subject,
                body=message,
                from_email='no-reply@mydriver.com',
                to=[user.email]
            )
            # Definindo o tipo de conteúdo como HTML
            email_message.content_subtype = 'html'
            email_message.send()

            # Retorna mensagem de sucesso
            return Response({'message': 'Conta ativada com sucesso! Você pode fazer login agora.'}, status=status.HTTP_200_OK)
        else:
            # Retorna erro caso o link de ativação seja inválido
            return Response({'error': 'Link de ativação inválido ou expirado.'}, status=status.HTTP_400_BAD_REQUEST)
