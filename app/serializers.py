from rest_framework import serializers
from .models import Contratante, ContratoEmprestimo, Parcela

class ContratanteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contratante
        exclude = []  
        extra_kwargs = {
            'user': {'read_only': True}
        }



class ParcelaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Parcela
        fields = '__all__'



class ContratoEmprestimoSerializer(serializers.ModelSerializer):
    parcelas = ParcelaSerializer(many=True, read_only=True)
    valor_total_com_juros = serializers.SerializerMethodField()
    contratante_nome = serializers.CharField(source='contratante.name', read_only=True)
   

    class Meta:
        model = ContratoEmprestimo
        fields = '__all__'

    def get_valor_total_com_juros(self, obj):
        return obj.valor_total_com_juros()