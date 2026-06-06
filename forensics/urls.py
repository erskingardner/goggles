from django.urls import path

from . import views

urlpatterns = [
    path("", views.incident_list, name="incident-list"),
    path("incidents/<slug:slug>/", views.incident_detail, name="incident-detail"),
    path("dumps/<int:pk>/", views.dump_detail, name="dump-detail"),
    path("api/v1/dumps/", views.api_dump_upload, name="api-dump-upload"),
    path(
        "api/v1/incidents/<slug:incident_slug>/dumps/",
        views.api_dump_upload,
        name="api-incident-dump-upload",
    ),
]
