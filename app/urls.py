from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .view_api import ContratanteViewSet, ContratoEmprestimoViewSet, ParcelaViewSet

from .views import (
    RegisterView, LoginView, ActivateAccountView, EstatisticaMensalView, LogoutView, gerar_pdf_enviar_email, EstatisticasEmprestimosView
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
    path('gerar-pdf/<int:contrato_id>/', gerar_pdf_enviar_email, name='gerar_pdf_contrato'),
    path('estatisticas-mensais/', EstatisticaMensalView.as_view(), name='estatisticas-mensais'),

]
