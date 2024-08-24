from django.urls import path
from .views import RegisterView,LoginView,TaskView,TaskMemberView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('login/', LoginView.as_view()),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('', TaskView.as_view()), 
    path('<int:pk>/', TaskView.as_view(), name='task-detail'),  
    
    path('<int:task_id>/status/', TaskView.as_view(), name='task-update-status'),  

    path('<int:task_id>/members/add/', TaskMemberView.as_view(), name='task-member-add'),  
    path('<int:task_id>/members/remove/', TaskMemberView.as_view(), name='task-member-remove'), 
    path('<int:task_id>/members/', TaskMemberView.as_view(), name='task-members-list'), 
]

