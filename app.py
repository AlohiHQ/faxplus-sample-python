from __future__ import print_function
import six
import traceback
from functools import wraps
import base64
import json
import requests
import os
import tempfile
from flask import Flask, request, Response, render_template, send_file, g

from faxplus import configuration
from faxplus.api.archives_api import ArchivesApi
from faxplus.api.files_api import FilesApi
from faxplus.api.numbers_api import NumbersApi
from faxplus.api.outbox_api import OutboxApi
from faxplus.api_client import ApiClient
from faxplus.api.accounts_api import AccountsApi

from faxplus.models.account import Account
from faxplus.models.member_detail import MemberDetail
from faxplus.models.payload_fax_modification import PayloadFaxModification
from faxplus.models.payload_number_modification import PayloadNumberModification
from faxplus.models.payload_outbox import PayloadOutbox
from faxplus.models.payload_outbox_modification import PayloadOutboxModification
from faxplus.rest import ApiException

app = Flask(__name__)

with open(os.path.join(os.path.dirname(__file__), 'config.json'), 'r') as f:
    config = json.load(f)
    if six.PY2:
        for k in config:
            config[k] = str(config[k])

client_id = config['client_id']
client_secret = config['client_secret']
client_basic_auth = base64.b64encode(six.b('{}:{}'.format(client_id, client_secret))).decode('utf-8')
redirect_uri = config['redirect_uri']
authorization_server_url = config['authorization_server_url']


class ApiClientFactory(object):
    @staticmethod
    def get_api_client(access_token=None):
        if access_token is None:
            access_token = g.access_token
        conf = configuration.Configuration()
        if config.get('resource_server_url'):
            conf.host = config['resource_server_url']
        conf.access_token = access_token
        return ApiClient(header_name='x-fax-clientid', header_value=client_id, configuration=conf)


def check_access_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ApiException as ex:
            if ex.status == 401:
                print('Access token is expired, refreshing access_token using refresh_token')
                url = "{}/token?grant_type=refresh_token&refresh_token={}".format(
                    authorization_server_url, request.cookies.get('refresh_token'))
                res = requests.post(
                    url,
                    headers={'Authorization': 'Basic {}'.format(client_basic_auth)}
                )
                if res.status_code != 200:
                    print('Failed to refresh access_token, logging user out | {}:{}'.format(res.status_code, res))
                    resp = Response('', status=401)
                    resp.set_cookie('access_token', '', path='/', httponly=True,
                                    expires='Thu, 01 Jan 1970 00:00:01 GMT')
                    resp.set_cookie('refresh_token', '', path='/', httponly=True,
                                    expires='Thu, 01 Jan 1970 00:00:01 GMT')
                    return resp
                data = res.json()
                access_token = data.get('access_token')
                g.access_token = access_token
                resp = f(*args, **kwargs)
                if not hasattr(resp, 'set_cookie'):
                    resp = Response(resp)
                resp.set_cookie('access_token', access_token, path='/', httponly=True)
                return resp
            else:
                print(traceback.format_exc())
                return ex.body, ex.status
        except Exception as ex:
            print(traceback.format_exc())
            raise ex
    return wrapper


@app.before_request
def extract_tokens():
    g.access_token = request.cookies.get('access_token')
    g.refresh_token = request.cookies.get('refresh_token')


@app.route("/")
@check_access_token
def index():
    login_url = ''
    is_logged_in = True
    if not g.access_token:
        is_logged_in = False
        login_url = "{}/login?response_type=code&client_id={}&redirect_uri={}&scope=all".format(
            authorization_server_url, client_id, redirect_uri)
    return render_template('index.html', is_logged_in=is_logged_in, login_url=login_url)


@app.route("/cb/")
def cb():
    token = request.args['code']
    payload = {
        'code': token,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
    }
    res = requests.post(
        authorization_server_url + '/token',
        data=payload,
        headers={'content-type': 'application/x-www-form-urlencoded',
                 'Authorization': 'Basic {}'.format(client_basic_auth)}
    )
    data = res.json()
    access_token = data.get('access_token')
    refresh_token = data.get('refresh_token')
    if not access_token:
        return Response(json.dumps(data), res.status_code)
    resp = Response("<script>window.location='/'</script>")
    resp.set_cookie('access_token', access_token, path='/', httponly=True)
    resp.set_cookie('refresh_token', refresh_token, path='/', httponly=True)
    return resp


@app.route("/accounts", methods=['GET', 'PUT'])
@check_access_token
def accounts_requests():
    method = request.method.lower()
    client = AccountsApi(ApiClientFactory.get_api_client())
    result = {}
    user_id = request.args.get('resource_id') or 'self'
    if method == 'get':
        if user_id == 'all':
            res = client.get_accounts()
            result = res.to_dict()
        else:
            account = client.get_user(user_id)
            result = account.to_dict()
    elif method == 'put':
        payload = Account(name=request.form['name'], lastname=request.form['lastname'])
        client.update_user(user_id, payload)
        result = {'result': 'Account updated successfully'}
    resp = Response(json.dumps(result))
    resp.headers['content-type'] = 'application/json'
    return resp


@app.route("/members", methods=['GET', 'PUT'])
@check_access_token
def members_requests():
    method = request.method.lower()
    client = AccountsApi(ApiClientFactory.get_api_client())
    result = {}
    if method == 'get':
        member_details = client.get_member_details(request.args['resource_id'])
        result = member_details.to_dict()
    elif method == 'put':
        quota = int(request.form['quota'])
        role = request.form['role']
        payload = MemberDetail(quota, role)
        client.update_member_details(request.args['resource_id'], payload)
        result = {'result': 'Member updated successfully'}
    resp = Response(json.dumps(result))
    resp.headers['content-type'] = 'application/json'
    return resp


@app.route("/numbers", methods=['GET', 'PUT', 'DELETE'])
@check_access_token
def numbers_requests():
    method = request.method.lower()
    client = NumbersApi(ApiClientFactory.get_api_client())
    result = {}
    if method == 'get':
        if request.args.get('resource_id'):
            number = client.get_number(request.args['resource_id'])
            result = number.to_dict()
        else:
            numbers = client.list_numbers()
            result = numbers.to_dict()
    elif method == 'delete':
        client.revoke_number(request.args['resource_id'])
        result = {'result': 'number revoked successfully'}
    elif method == 'put':
        payload = PayloadNumberModification(assigned_to=request.form['memberid'])
        client.update_number(request.args['resource_id'], payload)
        result = {'result': 'number assigned successfully'}
    resp = Response(json.dumps(result))
    resp.headers['content-type'] = 'application/json'
    return resp


@app.route("/archives", methods=['GET', 'POST', 'DELETE', 'PUT'])
@check_access_token
def archives_requests():
    method = request.method.lower()
    client = ArchivesApi(ApiClientFactory.get_api_client())
    result = {}
    if method == 'get':
        if request.args.get('resource_id'):
            fax = client.get_fax(request.args['resource_id'])
            result = fax.to_dict()
        else:
            faxes = client.list_faxes('self', category=request.args.get('category'))
            result = faxes.to_dict()
    elif method == 'delete':
        client.delete_fax(request.args['resource_id'])
        result = {'result': 'fax deleted successfully'}
    elif method == 'put':
        is_read = request.form['read'] == 'true'
        comment = request.form['comment']
        payload = PayloadFaxModification(is_read=is_read, comment=comment)
        client.update_fax(request.args['resource_id'], payload)
        result = {'result': 'fax updated successfully'}
    resp = Response(json.dumps(result))
    resp.headers['content-type'] = 'application/json'
    return resp


@app.route("/files", methods=['GET', 'POST'])
@check_access_token
def files_requests():
    method = request.method.lower()
    client = FilesApi(ApiClientFactory.get_api_client())
    result = {}
    if method == 'get':
        fax_id = request.args['resource_id']
        mime_type = 'application/pdf'  # can be 'image/tiff' too
        file_type = mime_type.split('/')[1]

        file_path = client.get_file(fax_id, format=file_type)
        return send_file(file_path, mimetype=mime_type, as_attachment=True, cache_timeout=1,
                         attachment_filename='fax-{}.{}'.format(fax_id, file_type))
    elif method == 'post':
        fax_file = request.files['fax_file']
        file_type = fax_file.mimetype.split('/')[1]
        fd, path = tempfile.mkstemp(suffix=".{}".format(file_type))
        try:
            fax_file.save(path)
            res = client.upload_file(path, format=file_type)
            result = res.to_dict()
        finally:
            os.remove(path)
    resp = Response(json.dumps(result))
    resp.headers['content-type'] = 'application/json'
    return resp


@app.route("/outbox", methods=['GET', 'POST', 'DELETE', 'PUT'])
@check_access_token
def outbox_requests():
    method = request.method.lower()
    client = OutboxApi(ApiClientFactory.get_api_client())
    result = {}
    if method == 'get':
        if request.args.get('resource_id'):
            res = client.get_outbox_fax(request.args.get('resource_id'))
            result = res.to_dict()
        else:
            res = client.list_outbox_faxes()
            result = res.to_dict()
    elif method == 'post':
        fax = PayloadOutbox(
            [request.form['to']],
            request.form['from'],
            [request.form['fax-file']],
            {
                "retry": {
                    "delay": 0,
                    "count": 0
                },
                "enhancement": True,
            },
        )
        client.send_fax(fax)
        result = {'result': 'outbox fax created successfully'}
    elif method == 'delete':
        client.delete_outbox_fax(request.args['resource_id'])
        result = {'result': 'outbox fax deleted successfully'}
    elif method == 'put':
        payload = PayloadOutboxModification(comment=request.form['comment'])
        res = client.update_outbox_fax(request.args.get('resource_id'), payload)
        print(res)
    resp = Response(json.dumps(result))
    resp.headers['content-type'] = 'application/json'
    return resp


if __name__ == '__main__':
    app.run('0.0.0.0', 8080, debug=True)
