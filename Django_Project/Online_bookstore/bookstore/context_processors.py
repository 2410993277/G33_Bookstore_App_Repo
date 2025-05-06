from .models import Section

def sections_processor(request):
    return {'sections': Section.objects.all()}