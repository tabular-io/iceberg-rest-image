# pip install "pyiceberg[s3fs,pyarrow]
# curl https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2023-01.parquet -o /tmp/yellow_tripdata_2023-01.parquet

import os

os.environ["AWS_DEFAULT_REGION"] = "eu-west-3"
os.environ["AWS_REGION"] = "eu-west-3"
os.environ["AWS_ACCESS_KEY_ID"] = "admin"
os.environ["AWS_SECRET_ACCESS_KEY"] = "adminadmin"


def run_iceberg():
    from pyiceberg.catalog.rest import RestCatalog

    catalog = RestCatalog(
        "default",
        **{
            "uri": "http://localhost:8181",
            "warehouse": "s3://test-bucket/",
            "s3.endpoint": "http://localhost:9020",
        },
    )
    import pyarrow.parquet as pq

    df = pq.read_table("/tmp/yellow_tripdata_2023-01.parquet")

    catalog.create_namespace("default")
    table = catalog.create_table(
        "default.taxi_dataset",
        schema=df.schema,
    )

    table.append(df)


    table = catalog.load_table("default.taxi_dataset")
    df = table.scan().to_arrow()
    print(len(df))


if __name__ == '__main__':
    run_iceberg()
