# QUY TRÌNH DEPLOY FRAPPE GOLD EDU

## Bước 1: Pull image mới từ Docker Hub
```bash
docker pull pcthuoc/frappe-gold-edu:latest
```

## Bước 2: Setup quyền truy cập và chạy configurator lần đầu
```bash
chown -R 1000:1000 ./repo/sites
chmod -R 775 ./repo/sites
docker compose build 
docker compose run --rm configurator
```

## Bước 3: Fix quyền truy cập sau khi configurator tạo file
```bash
chown -R 1000:1000 ./repo/sites
chmod -R 775 ./repo/sites
```

## Bước 4: Chạy lại configurator để đảm bảo cấu hình đúng
```bash
docker compose run --rm configurator
```

## Bước 5: Start tất cả containers
```bash
docker compose up -d
```

## Bước 6: Migrate database và clear cache (sau khi có thay đổi code)
```bash
docker exec -it frappe_docker_backend_1 bash -lc "bench --site frontend migrate"
docker exec -it frappe_docker_backend_1 bash -lc "bench --site frontend clear-cache"
docker exec -it frappe_docker_backend_1 bash -lc "bench --site frontend clear-website-cache"
```

## Bước 7: Build assets (nếu có thay đổi frontend)
```bash
docker exec -it frappe_docker_backend_1 bash -lc "bench build"
```

## Cấu hình Domain (thêm vào site config nếu cần)
```json
{
  "host_name": "english.goldedu.vn",
  "web_url": "https://english.goldedu.vn"
}
```