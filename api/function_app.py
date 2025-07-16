import os
import base64
import traceback
import re
import json
import logging
from datetime import datetime, timedelta
import azure.functions as func
import jwt # PyJWT in requirements
from azure.cosmos import CosmosClient, PermissionMode, exceptions
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, generate_container_sas, ContainerSasPermissions, generate_blob_sas, BlobSasPermissions

tables = {
    'events': os.environ.get('EVENTS_TABLE_NAME'),
    'modules': os.environ.get('MODULES_TABLE_NAME'),
    'policies': os.environ.get('POLICIES_TABLE_NAME'),
    'deployments': os.environ.get('DEPLOYMENTS_TABLE_NAME'),
    'change_records': os.environ.get('CHANGE_RECORDS_TABLE_NAME'),
    'config': os.environ.get('CONFIG_TABLE_NAME'),
}

buckets = {
    'modules': os.environ.get('MODULE_S3_BUCKET'),
    'policies': os.environ.get('POLICY_S3_BUCKET'),
    'change_records': os.environ.get('CHANGE_RECORD_S3_BUCKET'),
    'providers':     os.environ.get('PROVIDERS_S3_BUCKET'),
}


COSMOS_DB_ENDPOINT = os.getenv("COSMOS_DB_ENDPOINT")
COSMOS_DB_DATABASE = os.getenv("COSMOS_DB_DATABASE")

# Function is fronted by Easy Auth authentication and can safely use Anonymous authentication here
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.function_name(name="generic_api")
@app.route(route="api")
def handler(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body.", status_code=400)
    logging.info("req_body:")
    logging.info(req_body)

    event = req_body.get('event')
    try:
        if event == 'insert_db':
            return insert_db(req)
        elif event == 'read_db':
            return read_db(req)
        elif event == 'upload_file_base64':
            return upload_file_base64(req)
        elif event == 'upload_file_url':
            return upload_file_url(req)
        elif event == 'read_logs':
            return read_logs(req)
        elif event == 'generate_presigned_url':
            return generate_presigned_url(req)
        elif event == 'transact_write':
            return transact_write(req)
        else:
            return func.HttpResponse(json.dumps({"result":f"Invalid event type ({event})"}), status_code=400)
    except Exception as e:
        tb = traceback.format_exc()
        return func.HttpResponse(json.dumps({"result":f"Api error: {e}", "tb": tb}), status_code=500)
    
def transact_write(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body.", status_code=400)

    credential = DefaultAzureCredential()
    client = CosmosClient(COSMOS_DB_ENDPOINT, credential=credential)

    database = client.get_database_client(COSMOS_DB_DATABASE)
    responses = []

    for item in req_body['items']:
        try:
            if 'Put' in item:
                container_name = item['Put']['TableName']
                container_name = tables[container_name]
                container = database.get_container_client(container_name)
                put_item = item['Put']['Item']
                put_item.update({'id': get_id(put_item)}) # Reserved field that should not be used in InfraWeave rows, but is required by Cosmos DB
                
                container.upsert_item(put_item)
                responses.append({"operation": "Put", "status": "Success", "item_id": put_item["id"]})
                
            elif 'Delete' in item:
                container_name = item['Delete']['TableName']
                container_name = tables[container_name]
                container = database.get_container_client(container_name)
                delete_key = item['Delete']['Key']
                
                container.delete_item(item=delete_key['id'], partition_key=delete_key['partition_key'])
                responses.append({"operation": "Delete", "status": "Success", "item_id": delete_key["id"]})

        except exceptions.CosmosHttpResponseError as e:
            responses.append({
                "error": str(e)
            })
    return func.HttpResponse(
        body=json.dumps(responses),
        status_code=200,
        mimetype="application/json"
    )

_cache: dict[str, tuple[str, datetime]] = {} # subId -> (token, exp)

@app.function_name(name="get_token")
@app.route(route="token", methods=["POST"])
def get_token(req: func.HttpRequest) -> func.HttpResponse:
    OID_TO_SUBSCRIPTION = json.loads(os.getenv("OID_TO_SUBS_MAP_JSON", "{}"))

    def lookup_subscription_from_oid(oid: str):
        return OID_TO_SUBSCRIPTION.get(oid)
    
    # Extract bearer token
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return func.HttpResponse("No bearer presented", status_code=401)
    raw_jwt = auth[7:]

    # Decode JWT without signature (EasyAuth or custom will have already validated if needed)
    claims = jwt.decode(raw_jwt, options={"verify_signature": False})
    oid = claims.get("oid")

    # Lookup subscription from the calling identity
    sub_id = lookup_subscription_from_oid(oid) if oid else None
    if not sub_id:
        return func.HttpResponse(
            body=f"Unknown identity {oid}",
            status_code=403,
            mimetype="text/plain"
        )

    # Validate partition key in request matches subscription
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body.", status_code=400)
    pk = body.get("data", {}).get("partitionKey")
    if pk != sub_id:
        return func.HttpResponse("Partition not owned by caller", status_code=403)

    # Check in-memory cache
    now = datetime.utcnow()
    tok, exp = _cache.get(sub_id, (None, now))
    if tok and now < exp:
        return func.HttpResponse(tok, mimetype="application/json")

    # Generate resource tokens for the subscription-specific db-containers
    KEY       = os.getenv("COSMOS_DB_KEY")
    client = CosmosClient(COSMOS_DB_ENDPOINT, credential=KEY)
    db     = client.get_database_client(COSMOS_DB_DATABASE)

    user_id = sub_id
    try:
        db.create_user(body={ "id": user_id })
    except exceptions.CosmosResourceExistsError:
        # If it already exists, it's fine
        pass

    user = db.get_user_client(user_id)
    containers = [
        "deployments",     # Scales well within a single partitionkey
        "change-records",  # Scales well within a single partitionkey
        "events",          # TODO: refine; should partition further, every deployment can have thousands of events
        ]
    tokens = {}

    for coll in containers:
        perm = user.upsert_permission(
            {
            "id":             f"{user_id}-{coll}-perm",
            "permissionMode": PermissionMode.All,
            "resource":       f"dbs/{COSMOS_DB_DATABASE}/colls/{coll}",
            "resourcePartitionKey": [user_id],
            },
            resource_token_expiry_seconds=900
        )
        tokens[coll] = perm.properties["_token"]

    _cache[sub_id] = (json.dumps(tokens), now + timedelta(minutes=15))

    # Generate Blob container SAS for this subscription container
    PUBLIC_STORAGE_ACCOUNT_NAME = os.getenv("PUBLIC_STORAGE_ACCOUNT_NAME")
    STORAGE_ACCOUNT_URL = f"https://{PUBLIC_STORAGE_ACCOUNT_NAME}.blob.core.windows.net"
    cred = DefaultAzureCredential()
    blob_svc_client   = BlobServiceClient(account_url=STORAGE_ACCOUNT_URL, credential=cred)
    sas_start         = now
    sas_expiry        = now + timedelta(minutes=15)
    user_del_key      = blob_svc_client.get_user_delegation_key(sas_start, sas_expiry)

    for coll in ["change-records", "tf-state"]:
        container_name = f"workload-{coll}-{sub_id}"
        sas_token = generate_container_sas(
            account_name=blob_svc_client.account_name,
            container_name=container_name,
            user_delegation_key=user_del_key,
            permission=ContainerSasPermissions(read=True, write=True, list=True),
            start=sas_start,
            expiry=sas_expiry
        )
        tokens[container_name] = sas_token
    
    # Cache and return
    return func.HttpResponse(
        body=json.dumps(tokens),
        mimetype="application/json"
    )

def read_logs(req: func.HttpRequest) -> func.HttpResponse:
    from azure.monitor.query import LogsQueryClient
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body.", status_code=400)
    
    payload = req_body.get('data', {})
    job_id = payload.get('job_id')
    if not job_id:
        return func.HttpResponse("Missing job_id.", status_code=400)

    log_analytics_workspace_id = os.getenv("LOG_ANALYTICS_WORKSPACE_ID")

    try:
        credential = DefaultAzureCredential()
        client = LogsQueryClient(credential)
        
        # Define a query to retrieve logs for the given container group
        query = f"""
        ContainerInstanceLog_CL
        | where ContainerGroup_s == "{job_id}"
        | order by TimeGenerated asc
        """

        timespan = timedelta(days=365)
        response = client.query_workspace(log_analytics_workspace_id, query, timespan=timespan)

        import json
        import datetime

        def json_serial(obj):
            if isinstance(obj, (datetime.datetime, datetime.date)):
                return obj.isoformat()
            raise TypeError(f"Type {obj.__class__.__name__} not serializable")

    
        events = []
        if response.tables:
            for table in response.tables:
                events.extend([{"message": row["Message"]} for row in table.rows])

    except Exception as e:
        return func.HttpResponse(f"Error querying logs: {e}", status_code=500)
    
    return func.HttpResponse(
        body=json.dumps({"events": events}, default=json_serial),
        status_code=200,
        mimetype="application/json"
    )

def generate_presigned_url(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body.", status_code=400)

    req_body = req.get_json()
    payload = req_body.get('data')
    container_name = payload.get("bucket_name")
    container_name = buckets[container_name]
    blob_name = payload.get("key")
    expires_in = payload.get("expires_in", 3600)
    sas_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    account_name = os.getenv("PUBLIC_STORAGE_ACCOUNT_NAME")

    blob_service_client = BlobServiceClient(
        account_url=f"https://{account_name}.blob.core.windows.net",
        credential=DefaultAzureCredential()
    )
    
    user_delegation_key = blob_service_client.get_user_delegation_key(
        key_start_time=datetime.utcnow(),
        key_expiry_time=sas_expiry
    )
    sas_token = generate_blob_sas(
        account_name=account_name,
        container_name=container_name,
        blob_name=blob_name,
        permission=BlobSasPermissions(read=True),  # Use read permissions for download access
        expiry=sas_expiry,
        user_delegation_key=user_delegation_key,
    )

    blob_url = f"https://{account_name}.blob.core.windows.net/{container_name}/{blob_name}?{sas_token}"

    return func.HttpResponse(
        json.dumps({"url": blob_url}),
        status_code=200,
        mimetype="application/json"
    )

def get_id(body):
    raw = f"{body['PK']}~{body['SK']}".lower()
    safe = re.sub(r'[^0-9a-z]', '_', raw)
    return safe

def insert_db(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body.", status_code=400)

    container_name = req_body.get('table')
    container_name = tables[container_name]
    item = req_body.get('data')
    item.update({'id': get_id(item)}) # Reserved field that should not be used in InfraWeave rows, but is required by Cosmos DB

    credential = DefaultAzureCredential()
    client = CosmosClient(COSMOS_DB_ENDPOINT, credential=credential)

    database = client.get_database_client(COSMOS_DB_DATABASE)
    container = database.get_container_client(container_name)

    try:
        response = container.upsert_item(body=item)
        return func.HttpResponse(json.dumps(response), status_code=200)
    except exceptions.CosmosHttpResponseError as e:
        print(f'Error inserting item: {e}')
        return func.HttpResponse(f'Error inserting item: {e}', status_code=500)

def read_db(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body.", status_code=400)

    container_name = req_body.get('table')
    container_name = tables[container_name]
    query = req_body.get('data').get('query')

    credential = DefaultAzureCredential()
    client = CosmosClient(COSMOS_DB_ENDPOINT, credential=credential)

    database = client.get_database_client(COSMOS_DB_DATABASE)
    container = database.get_container_client(container_name)

    try:
        items = list(container.query_items(
            query=query,
            enable_cross_partition_query=True
        ))
        logging.info(f"Read operation succeeded, found {len(items)} items.")
        return func.HttpResponse(json.dumps(items), status_code=200)
    except exceptions.CosmosHttpResponseError as e:
        print(f'Error querying items: {e}')
        return func.HttpResponse(json.dumps({"message": f"error querying: {e}"}), status_code=500)

def upload_file_base64(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body.", status_code=400)

    
    account_name = os.getenv("PUBLIC_STORAGE_ACCOUNT_NAME")
    blob_service_client = BlobServiceClient(
        account_url=f"https://{account_name}.blob.core.windows.net",
        credential=DefaultAzureCredential()
    )

    payload = req_body.get('data')
    container_name = payload.get('bucket_name')
    container_name = buckets[container_name]
    base64_body = payload.get('base64_content')
    blob_name = payload.get('key')
    binary_body = base64.b64decode(base64_body)
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
    blob_client.upload_blob(binary_body, overwrite=True)
    print(f"Blob {blob_name} uploaded to container {container_name} successfully.")
    response_body = {
        "status": f"Blob {blob_name} uploaded to container {container_name} successfully."
    }
    return func.HttpResponse(
        json.dumps(response_body),
        status_code=200,
        mimetype="application/json"
    )

def upload_file_url(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body.", status_code=400)

    payload = req_body.get('data', {})
    container_key = payload.get('bucket_name')
    container_name = buckets.get(container_key)
    if not container_name:
        return func.HttpResponse(f"Unknown bucket_name '{container_key}'", status_code=400)

    blob_name = payload.get('key')
    download_url = payload.get('url')

    # Azure Blob client
    account_name = os.getenv("PUBLIC_STORAGE_ACCOUNT_NAME")
    blob_service = BlobServiceClient(
        account_url=f"https://{account_name}.blob.core.windows.net",
        credential=DefaultAzureCredential()
    )
    blob_client = blob_service.get_blob_client(container=container_name, blob=blob_name)

    # check if blob already exists
    if blob_client.exists():
        return func.HttpResponse(
            json.dumps({"object_already_exists": True}),
            status_code=200,
            mimetype="application/json"
        )

    # download from URL and upload
    try:
        with urllib.request.urlopen(download_url) as resp:
            blob_client.upload_blob(resp, overwrite=False)
    except Exception as e:
        return func.HttpResponse(f"Error uploading blob: {e}", status_code=500)

    return func.HttpResponse(
        json.dumps({"object_already_exists": False}),
        status_code=200,
        mimetype="application/json"
    )
