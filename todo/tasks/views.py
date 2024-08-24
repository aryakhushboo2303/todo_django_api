
from rest_framework.views import APIView
from .serializers import RegisterSerializer,LoginSerializer,TaskSerializer,TaskMemberSerializer
from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied
from .models import Task,TaskMember
from django.contrib.auth.models import User

class RegisterView(APIView):
    def post(self,request):
        try:
            serializer=RegisterSerializer(data=request.data)
            if not serializer.is_valid():
                print(serializer.errors)
                return Response({
                    'data': serializer.errors,
                    'message': 'something went wrong'
                },status=status.HTTP_400_BAD_REQUEST)
            serializer.save()
            return Response({
                    'data': {},
                    'message': 'success'
                },status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({
                'data' : {},
                'message' : 'here error'
            },status = status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self,request):
        try:
            serializer=LoginSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    'data': serializer.errors,
                    'message': 'something went wrong'
                },status=status.HTTP_400_BAD_REQUEST)
            response=serializer.get_jwt_token(serializer.data)
            return Response({
                'data' : response,
                'message': 'token granted'
            },status=status.HTTP_200_OK)
        except Expection as e:
            return Response({
                'data' : {},
                'message' : 'something went wrong'
            },status = status.HTTP_400_BAD_REQUEST)

class TaskView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self,request):
        serializer=TaskSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({'data': serializer.errors,'message': 'invalid details'},status=status.HTTP_400_BAD_REQUEST)
        task = serializer.save(created_by=request.user)
        TaskMember.objects.create(task=task, user=request.user)
        return Response({'data': serializer.data,'message': 'created'},status=status.HTTP_201_CREATED)
    
    def get(self,request,pk=None):
        if pk is None:
            tasks=Task.objects.all()
            serializer=TaskSerializer(tasks,many=True)
            return Response({'data': serializer.data,'message': 'displayed'},status=status.HTTP_201_CREATED)
        else:
            task=get_object_or_404(Task,pk=pk)
            serializer=TaskSerializer(task)
            return Response({'data': serializer.data,'message': 'displayed'},status=status.HTTP_201_CREATED)

    def put(self,request,pk):
        task=get_object_or_404(Task,pk=pk,created_by=request.user)
        serializer=TaskSerializer(task,data=request.data,partial=False)
        if not serializer.is_valid():
            return Response({'data': serializer.errors,'message': 'bad status'},status=status.HTTP_400_BAD_REQUEST)
        serializer.save()
        return Response({'data': serializer.data,'message': 'created'},status=status.HTTP_200_OK)

    def patch(self, request, task_id):
        task = get_object_or_404(Task, pk=task_id, created_by=request.user)
        new_status = request.data.get('status')
        if new_status not in ['Todo', 'Inprogress', 'Done']:
            return Response({'detail': 'Invalid status.'}, status=status.HTTP_400_BAD_REQUEST)
        task.status = new_status
        task.save()
        serializer = TaskSerializer(task)
        return Response({'data': serializer.data, 'message': 'Task status updated'}, status=status.HTTP_200_OK)

    def delete(self,request,pk):
        task=get_object_or_404(Task,pk=pk,created_by=request.user)
        task.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class TaskMemberView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, task_id):
        task = get_object_or_404(Task, pk=task_id)
        user_ids = request.data.get('users')
        if task.created_by != request.user:
            raise PermissionDenied("You are not allowed to remove members to this task.")

        for user_id in user_ids:
            user = get_object_or_404(User, pk=user_id)
            TaskMember.objects.filter(task=task, user=user).delete()

        return Response({'message': 'Members removed from the task.'}, status=status.HTTP_204_NO_CONTENT)

    def post(self, request,task_id):
        user_ids = request.data.get('users')
        task = get_object_or_404(Task, pk=task_id)
        if task.created_by != request.user:
            raise PermissionDenied("You are not allowed to add members to this task.")

        for user_id in user_ids:
            user = get_object_or_404(User, pk=user_id)
            if TaskMember.objects.filter(task=task, user=user).exists():
                continue
            TaskMember.objects.create(task=task, user=user)
        return Response({'message': 'Members added to the task.'}, status=status.HTTP_201_CREATED)

    def get(self, request, task_id):    
        task = get_object_or_404(Task, pk=task_id)
        members = task.members.all() 
        serializer = TaskMemberSerializer(members, many=True)  
        return Response({'data': serializer.data, 'message': 'Members retrieved successfully'}, status=status.HTTP_200_OK)

    



