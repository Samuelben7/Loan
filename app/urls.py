from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .view_api import ContratanteViewSet, ContratoEmprestimoViewSet, ParcelaViewSet

from .views import (
    RegisterView, EstatisticaParcelasPagasView, LoginView, ResetPasswordPageView, ActivateAccountView, EstatisticaMensalView, PasswordResetRequestView, LogoutView, GerarPDFEnviarEmailView, EstatisticasEmprestimosView
)

router = DefaultRouter()
router.register(r'contratantes', ContratanteViewSet)
router.register(r'contratos', ContratoEmprestimoViewSet)
router.register(r'parcelas', ParcelaViewSet)

urlpatterns = [
    path('', include(router.urls)),

    # Registro
    path('register/', RegisterView.as_view(), name='register'),
    path('activate/<str:uidb64>/<str:token>/', ActivateAccountView.as_view(), name='activate_account'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('estatisticas/', EstatisticasEmprestimosView.as_view(), name='estatisticas-emprestimos'),
    path('gerar-pdf/<int:contrato_id>/', GerarPDFEnviarEmailView.as_view(), name='gerar_pdf'),
    path('estatisticas-mensais/', EstatisticaMensalView.as_view(), name='estatisticas-mensais'),
    path('reset-password/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('reset-password/<uidb64>/<token>/', ResetPasswordPageView.as_view(), name='password_reset'),
    path('pagas/', EstatisticaParcelasPagasView.as_view(), name='pagas')

]
