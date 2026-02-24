def get_device_info(request):
    return request.headers.get('User-Agent', 'unknown')