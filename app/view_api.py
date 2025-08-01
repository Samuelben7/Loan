from rest_framework.viewsets import ModelViewSet
from .models import Contratante, ContratoEmprestimo, Parcela
from .serializers import ContratanteSerializer, ContratoEmprestimoSerializer, ParcelaSerializer
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status

class ContratanteViewSet(ModelViewSet):
    serializer_class = ContratanteSerializer
    permission_classes = [IsAuthenticated]
    queryset = Contratante.objects.all()  # <-- definir mesmo com get_queryset

    def get_queryset(self):
        return Contratante.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)




class ContratoEmprestimoViewSet(ModelViewSet):
    serializer_class = ContratoEmprestimoSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['contratante']
    queryset = ContratoEmprestimo.objects.all()  # <-- definir

    def get_queryset(self):
        return ContratoEmprestimo.objects.filter(contratante__user=self.request.user)


class ParcelaViewSet(ModelViewSet):
    serializer_class = ParcelaSerializer
    permission_classes = [IsAuthenticated]
    queryset = Parcela.objects.all()  # <-- definir

    def get_queryset(self):
        return Parcela.objects.filter(contrato__contratante__user=self.request.user)

    @action(detail=True, methods=['post'])
    def marcar_como_pago(self, request, pk=None):
        parcela = self.get_object()
        parcela.paga = True
        parcela.data_pagamento = timezone.now().date()
        parcela.save()
        return Response({'status': 'Parcela marcada como paga'}, status=status.HTTP_200_OK)
