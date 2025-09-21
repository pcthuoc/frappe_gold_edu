chown -R 1000:1000 ./repo/sites
chmod -R 775 ./repo/sites
docker compise build 
docker compose run --rm configurator


docker exec -it frappe_docker-backend-1 bash -lc "bench --site frontend migrate"
docker exec -it frappe_docker-backend-1 bash -lc "bench --site frontend clear-cache"
docker exec -it frappe_docker-backend-1 bash -lc "bench --site frontend clear-website-cache"


docker exec -it frappe_docker-backend-1 bash -lc "bench build"

chown -R 1000:1000 ./repo/sites



 "host_name": "english.goldedu.vn",
 "web_url": "https://english.goldedu.vn"