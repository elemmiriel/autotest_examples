import pytest
import requests
import hashlib
import jwt
import time


def __get_signature(endpoint, salt):
    method = 'GET'
    to_hash = endpoint + method + salt
    to_hash = to_hash.encode()
    signature = hashlib.sha256(to_hash).hexdigest()
    return signature


@pytest.mark.php
def test_{некая_внешняя_система}_users(get_evn):
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/users'
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    get_users = requests.get(endpoint + '?filter%5Bemail%5D=' + get_evn['email'], headers=header)
    assert get_users.status_code == 200
    assert len(get_users.json()['data']) == 7
    assert get_users.json()['data']['id'] is not None
    assert get_users.json()['data']['email'] is not None
    assert get_users.json()['data']['isEmailConfirmed'] is not None
    assert get_users.json()['data']['firstName'] is not None
    assert get_users.json()['data']['lastName'] is not None
    assert 'gender' in get_users.json()['data']
    assert 'birthDate' in get_users.json()['data']
    assert get_users.json()['status'] == 200
    assert get_users.json()['isError'] is False
    assert get_users.json()['errors'] == {}


@pytest.mark.php
def test_{некая_внешняя_система}_users_error_unauthorized(get_evn):
    header = {'Accept': 'application/json'}
    get_users = requests.get(get_evn['url'] + '/api/{некая_внешняя_система}/v1/users?filter%5Bemail%5D=' + get_evn['email'],
                             headers=header)
    assert get_users.status_code == 401
    assert len(get_users.json()['data']) == 0
    assert get_users.json()['status'] == 401
    assert get_users.json()['isError'] is True
    assert len(get_users.json()['errors']) == 5


@pytest.mark.php
@pytest.mark.parametrize('email, error, message', [('', ['The filter.email field is required.'], 'The given data was '
                                                                                                  'invalid.'),
                                                   ('get_evn[\'email\']', ['The filter.email must be a valid email '
                                                                              'address.'], 'The given data was '
                                                                                            'invalid.'),
                                                   (' some email.com', ['The filter.email must be a valid '
                                                                                'email address.'], 'The given data '
                                                                                                    'was invalid.'),
                                                   ('123', ['The filter.email must be a valid email address.'],
                                                    'The given data was invalid.')])
def test_{некая_внешняя_система}_users_error_invalid(get_evn, email, error, message):
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/users'
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    if email == 'get_evn[\'email\']':
        email = eval(email).replace('@', '')
    get_users = requests.get(endpoint + '?filter%5Bemail%5D=' + email, headers=header)
    assert get_users.status_code == 422
    assert len(get_users.json()['data']) == 0
    assert get_users.json()['status'] == 422
    assert get_users.json()['isError'] is True
    assert len(get_users.json()['errors']) == 2
    assert get_users.json()['errors']['filter.email'] == error
    assert get_users.json()['errors']['message'] == message


@pytest.mark.php
def test_{некая_внешняя_система}_user_program(get_evn):
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/users/' + get_evn['user_id'] + '/programs'
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    get_user_program = requests.get(endpoint, headers=header)
    assert get_user_program.status_code == 200
    assert len(get_user_program.json()['data']) != 0
    assert get_user_program.json()['data'][0]['id'] is not None
    assert get_user_program.json()['status'] == 200
    assert get_user_program.json()['isError'] is False
    assert get_user_program.json()['errors'] == {}


@pytest.mark.php
def test_{некая_внешняя_система}_user_program_error_unauthorized(get_evn):
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/users/' + get_evn['user_id'] + '/programs'
    header = {'Accept': 'application/json'}
    get_user_program = requests.get(endpoint, headers=header)
    assert get_user_program.status_code == 401
    assert len(get_user_program.json()['data']) == 0
    assert get_user_program.json()['status'] == 401
    assert get_user_program.json()['isError'] is True
    assert len(get_user_program.json()['errors']) == 5


@pytest.mark.php
@pytest.mark.parametrize('program_id', ['1437', '3652', '174', '1437'])
def test_{некая_внешняя_система}_get_program(get_evn, program_id):
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/programs/' + program_id
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    get_program = requests.get(endpoint, headers=header)
    assert get_program.status_code == 200
    assert len(get_program.json()['data']) == 10
    assert get_program.json()['data']['id'] is not None
    assert get_program.json()['data']['kind'] is not None
    assert get_program.json()['data']['category'] is not None
    assert get_program.json()['data']['programId'] is not None
    assert get_program.json()['data']['title'] is not None
    assert get_program.json()['data']['description'] is not None
    assert 'imageUrl' in get_program.json()['data']
    assert get_program.json()['data']['duration'] is not None
    assert 'url' in get_program.json()['data']
    assert get_program.json()['data']['updatedAt'] is not None
    assert get_program.json()['status'] == 200
    assert get_program.json()['isError'] is False
    assert get_program.json()['errors'] == {}


@pytest.mark.php
@pytest.mark.parametrize('program_id', ['-1', 'aaa'])
def test_{некая_внешняя_система}_get_program_error(get_evn, program_id):
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/programs/' + program_id
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    get_program = requests.get(endpoint, headers=header)
    assert get_program.status_code == 404
    assert len(get_program.json()['data']) == 0
    assert get_program.json()['status'] == 404
    assert get_program.json()['isError'] is True
    assert len(get_program.json()['errors']) == 5


@pytest.mark.php
def test_{некая_внешняя_система}_get_program_error_unauthorized(get_evn):
    program_id = '1437'
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/programs/' + program_id
    header = {'Accept': 'application/json'}
    get_program = requests.get(endpoint, headers=header)
    assert get_program.status_code == 401
    assert len(get_program.json()['data']) == 0
    assert get_program.json()['status'] == 401
    assert get_program.json()['isError'] is True
    assert len(get_program.json()['errors']) == 5


@pytest.mark.php
def test_{некая_внешняя_система}_all_programs(get_evn):
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/programs'
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    get_all_programs = requests.get(endpoint, headers=header)
    assert get_all_programs.status_code == 200
    assert len(get_all_programs.json()['data']) == 10
    assert get_all_programs.json()['data'][0]['id'] is not None
    assert get_all_programs.json()['data'][0]['kind'] is not None
    assert get_all_programs.json()['data'][0]['category'] is not None
    assert get_all_programs.json()['data'][0]['title'] is not None
    assert get_all_programs.json()['data'][0]['description'] is not None
    assert 'imageUrl' in get_all_programs.json()['data'][0]
    assert get_all_programs.json()['data'][0]['duration'] is not None
    assert 'url' in get_all_programs.json()['data'][0]
    assert get_all_programs.json()['data'][0]['updatedAt'] is not None
    assert get_all_programs.json()['status'] == 200
    assert get_all_programs.json()['isError'] is False
    assert get_all_programs.json()['errors'] == {}


@pytest.mark.php
def test_{некая_внешняя_система}_all_programs_error_unauthorized(get_evn):
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/programs'
    header = {'Accept': 'application/json'}
    get_all_programs = requests.get(endpoint, headers=header)
    assert get_all_programs.status_code == 401
    assert len(get_all_programs.json()['data']) == 0
    assert get_all_programs.json()['status'] == 401
    assert get_all_programs.json()['isError'] is True
    assert len(get_all_programs.json()['errors']) == 5


@pytest.mark.php
def test_{некая_внешняя_система}_all_programs_page_number(get_evn):
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/programs'
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    all_programs_number1 = requests.get(endpoint + '?page[number]=1', headers=header)
    assert all_programs_number1.status_code == 200
    all_programs_number3 = requests.get(endpoint + '?page[number]=3', headers=header)
    assert all_programs_number3.status_code == 200
    for i in all_programs_number1.json()['data']:
        for j in all_programs_number3.json()['data']:
            assert i['id'] != j['id']


@pytest.mark.php
def test_{некая_внешняя_система}_all_programs_page_size(get_evn):
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/programs'
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    page_size1 = requests.get(endpoint + '?page[size]=1', headers=header)
    assert page_size1.status_code == 200
    page_size50 = requests.get(endpoint + '?page[size]=50', headers=header)
    assert page_size50.status_code == 200
    assert len(page_size1.json()['data']) < len(page_size50.json()['data'])


@pytest.mark.php
@pytest.mark.parametrize('page_size, error', [('-1', ['The page.size must be at least 1.']), ('1-1', ['The page.size '
                                                                                                      'must be an '
                                                                                                      'integer.']),
                                              ('101', ['The page.size must not be greater than 50.'])])
def test_{некая_внешняя_система}_all_programs_page_size_error(get_evn, page_size, error):
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/programs'
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    url = endpoint + ('&' if '?' in endpoint else '?')
    page_size = requests.get(url + 'page%5Bsize%5D=' + page_size, headers=header)
    assert page_size.status_code == 422
    assert page_size.json()['status'] == 422
    assert page_size.json()['data'] == {}
    assert page_size.json()['isError'] is True
    assert page_size.json()['errors']['message'] == 'The given data was invalid.'
    assert page_size.json()['errors']['page.size'] == error


@pytest.mark.php
@pytest.mark.parametrize('page_number, error', [('-1', ['The page.number must be at least 1.']), ('1-1',
                                                                                                  ['The page.number '
                                                                                                   'must be an '
                                                                                                   'integer.'])])
def test_{некая_внешняя_система}_all_programs_page_number_error(get_evn, page_number, error):
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/programs'
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    url = endpoint + ('&' if '?' in endpoint else '?')
    page_number = requests.get(url + 'page%5Bnumber%5D=' + str(page_number), headers=header)
    assert page_number.status_code == 422
    assert page_number.json()['status'] == 422
    assert page_number.json()['data'] == {}
    assert page_number.json()['isError'] is True
    assert page_number.json()['errors']['message'] == 'The given data was invalid.'
    assert page_number.json()['errors']['page.number'] == error


@pytest.mark.php
def test_{некая_внешняя_система}_all_programs_page_all_error(get_evn):
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/programs'
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    all_programs_page = requests.get(
        endpoint + '?page%5Bnumber%5D=-1&page%5Bsize%5D=-1',
        headers=header)
    assert all_programs_page.status_code == 422
    assert all_programs_page.json()['status'] == 422
    assert all_programs_page.json()['data'] == {}
    assert all_programs_page.json()['isError'] is True
    assert len(all_programs_page.json()['errors']) == 3
    assert all_programs_page.json()['errors']['page.number'] == ['The page.number must be at least 1.']
    assert all_programs_page.json()['errors']['page.size'] == ['The page.size must be at least 1.']
    assert all_programs_page.json()['errors']['message'] == 'The given data was invalid.'


@pytest.mark.php
@pytest.mark.parametrize('redirect_url', ['https://{некий_сайт}/education', 'https://{некий_сайт}/posts', 'https://{некий_сайт}'])
def test_{некая_внешняя_система}_authorize(get_evn, redirect_url):
    payload = {
        "iss": "https://www.{некая_внешняя_система}.by/",
        "sub": get_evn['user_id'],
        "eml": get_evn['email'],
        "iat": int(time.time()),
        "exp": int(time.time()) + 30
    }
    id_token = jwt.encode(payload, get_evn['{некая_внешняя_система}Secret'], algorithm='HS256')
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/authorize'
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    get_authorize = requests.get(endpoint + '?redirectUri=' + redirect_url + '&idToken=' + id_token, headers=header,
                                 allow_redirects=False)
    assert get_authorize.status_code == 302
    assert redirect_url in get_authorize.text


@pytest.mark.php
@pytest.mark.parametrize('redirect_url', ['123', 'abc', '{некий_сайт}'])
def test_{некая_внешняя_система}_authorize_redirect_error(get_evn, redirect_url):
    payload = {
        "iss": "https://www.{некая_внешняя_система}.by/",
        "sub": get_evn['user_id'],
        "eml": get_evn['email'],
        "iat": int(time.time()),
        "exp": int(time.time()) + 30
    }
    id_token = jwt.encode(payload, get_evn['{некая_внешняя_система}Secret'], algorithm='HS256')
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/authorize'
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    get_authorize = requests.get(endpoint + '?redirectUri=' + redirect_url + '&idToken=' + id_token, headers=header,
                                 allow_redirects=False)
    assert get_authorize.status_code == 422
    assert get_authorize.json()['status'] == 422
    assert get_authorize.json()['data'] == {}
    assert get_authorize.json()['isError'] is True
    assert len(get_authorize.json()['errors']) == 2
    assert get_authorize.json()['errors']['redirectUri'] == ['The redirect uri format is invalid.']
    assert get_authorize.json()['errors']['message'] == 'The given data was invalid.'


@pytest.mark.php
@pytest.mark.parametrize('token', ['123', 'abc', '..'])
def test_{некая_внешняя_система}_authorize_token_error(get_evn, token):
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/authorize'
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    get_authorize = requests.get(endpoint + '?redirectUri=https://{некий_сайт}' + '&idToken=' + token, headers=header,
                                 allow_redirects=False)
    assert get_authorize.status_code == 400
    assert get_authorize.json()['status'] == 400
    assert get_authorize.json()['data'] == {}
    assert get_authorize.json()['isError'] is True
    assert get_authorize.json()['errors']['message'] == 'Invalid token'


@pytest.mark.php
def test_{некая_внешняя_система}_authorize_token_expired_error(get_evn):
    payload = {
        "iss": "https://www.{некая_внешняя_система}.by/",
        "sub": get_evn['user_id'],
        "eml": get_evn['email'],
        "iat": int(time.time()),
        "exp": int(time.time())
    }
    id_token = jwt.encode(payload, get_evn['{некая_внешняя_система}Secret'], algorithm='HS256')
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/authorize'
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    get_authorize = requests.get(endpoint + '?redirectUri=https://{некий_сайт}' + '&idToken=' + id_token, headers=header,
                                 allow_redirects=False)
    assert get_authorize.status_code == 401
    assert get_authorize.json()['status'] == 401
    assert get_authorize.json()['data'] == {}
    assert get_authorize.json()['isError'] is True
    assert get_authorize.json()['errors']['message'] == 'Token expired'


@pytest.mark.php
def test_{некая_внешняя_система}_authorize_all_error(get_evn):
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/authorize'
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    get_authorize = requests.get(endpoint, headers=header,
                                 allow_redirects=False)
    assert get_authorize.status_code == 422
    assert get_authorize.json()['status'] == 422
    assert get_authorize.json()['data'] == {}
    assert get_authorize.json()['isError'] is True
    assert len(get_authorize.json()['errors']) == 3
    assert get_authorize.json()['errors']['idToken'] == ['The id token field is required.']
    assert get_authorize.json()['errors']['redirectUri'] == ['The redirect uri field is required.']
    assert get_authorize.json()['errors']['message'] == 'The given data was invalid.'


@pytest.mark.php
def test_{некая_внешняя_система}_authorize_secret_error(get_evn):
    payload = {
        "iss": "https://www.{некая_внешняя_система}.by/",
        "sub": get_evn['user_id'],
        "eml": get_evn['email'],
        "iat": int(time.time()),
        "exp": int(time.time()) + 30
    }
    id_token = jwt.encode(payload, get_evn['salt'], algorithm='HS256')
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/authorize'
    signature = __get_signature(endpoint, get_evn['salt'])
    header = {'Accept': 'application/json', 'X-Signature': signature}
    get_authorize = requests.get(endpoint + '?redirectUri=https://{некий_сайт}' + '&idToken=' + id_token, headers=header,
                                 allow_redirects=False)
    assert get_authorize.status_code == 400
    assert get_authorize.json()['status'] == 400
    assert get_authorize.json()['data'] == {}
    assert get_authorize.json()['isError'] is True
    assert get_authorize.json()['errors']['message'] == 'Invalid sign'


@pytest.mark.php
def test_{некая_внешняя_система}_authorize_unauthorized_error(get_evn):
    payload = {
        "iss": "https://www.{некая_внешняя_система}.by/",
        "sub": get_evn['user_id'],
        "eml": get_evn['email'],
        "iat": int(time.time()),
        "exp": int(time.time()) + 30
    }
    id_token = jwt.encode(payload, get_evn['{некая_внешняя_система}Secret'], algorithm='HS256')
    endpoint = get_evn['url'] + '/api/{некая_внешняя_система}/v1/authorize'
    header = {'Accept': 'application/json'}
    get_authorize = requests.get(endpoint + '?redirectUri=https://{некий_сайт}' + '&idToken=' + id_token, headers=header,
                                 allow_redirects=False)
    assert get_authorize.status_code == 401
    assert get_authorize.json()['status'] == 401
    assert get_authorize.json()['data'] == {}
    assert get_authorize.json()['isError'] is True
    assert get_authorize.json()['errors']['message'] == 'Unauthorized.'
