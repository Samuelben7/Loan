from rest_framework.viewsets import ModelViewSet
from .models import Contratante, ContratoEmprestimo, Parcela
from .serializers import ContratanteSerializer, ContratoEmprestimoSerializer, ParcelaSerializer
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status

class ContratanteViewSet(ModelViewSet):
    queryset = Contratante.objects.all()
    serializer_class = ContratanteSerializer
    permission_classes = [IsAuthenticated]

class ContratoEmprestimoViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = ContratoEmprestimo.objects.all()
    serializer_class = ContratoEmprestimoSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['contratante']

class ParcelaViewSet(ModelViewSet):
    queryset = Parcela.objects.all()
    serializer_class = ParcelaSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=['post'])
    def marcar_como_pago(self, request, pk=None):
        parcela = self.get_object()
        parcela.paga = True
        parcela.save()
        return Response({'status': 'Parcela marcada como paga'}, status=status.HTTP_200_OK)
