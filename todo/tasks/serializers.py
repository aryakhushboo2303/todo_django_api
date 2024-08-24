from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Task,TaskMember

class RegisterSerializer(serializers.Serializer):
    first_name=serializers.CharField()
    last_name=serializers.CharField()
    username=serializers.CharField()
    password=serializers.CharField()

    
    def validate(self,data):
        if User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError('username already exists')
        return data
    
    def create(self,validated_data):
        user=User.objects.create(first_name=validated_data['first_name'],last_name=validated_data['last_name'],username=validated_data['username'])
        user.set_password(validated_data['password'])
        user.save()  
        return user

class LoginSerializer(serializers.Serializer):
    username=serializers.CharField()
    password=serializers.CharField()

    def validate(self,data):
        if not User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError('account not found')
        return data

    def get_jwt_token(self,validated_data):
        user=authenticate(username=validated_data['username'],password=validated_data['password'])
        if not user:
            return { 'data': {}, 'message': 'user not present'}
        refresh=RefreshToken.for_user(user)
        return {'data': {'token': { 'refresh': str(refresh),'access': str(refresh.access_token)}},'message': 'login access'}

class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        
        fields = ['id','title','description','due_date','status','created_by']
        extra_kwargs = {
            'created_by': {'read_only': True}  
        }

class TaskMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = TaskMember
        fields = ['id','task','user']