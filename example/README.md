# iceberg-rest example

how start the example stack

```shell
docker compose up -d
```

then 

```shell
pip install "pyiceberg[s3fs,pyarrow]
curl https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2023-01.parquet -o /tmp/yellow_tripdata_2023-01.parquet
python3 iceberg_s3_example.py
```