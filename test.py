import requests

# Frontend imitation

r = requests.post('http://127.0.0.1:5000?username=Anton&password=555364')

print(r.json()[0]['JWT'])
