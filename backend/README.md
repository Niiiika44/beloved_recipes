Поднять окружение:
```
docker compose -f infra/docker-compose.yml up -d
```
Для запуска необходим заполненный .env файл, который создаётся по примеру .env.example:
```
cp infra/.env.example infra/.env
```
