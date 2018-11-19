import abc
import datetime
import json
import logging
import hashlib
import re
import uuid
from argparse import ArgumentParser
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Union

from scoring import get_score, get_interests

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field(metaclass=abc.ABCMeta):

    name = None

    def __init__(self, required: bool, nullable: bool):
        self._required = required
        self._nullable = nullable
        self._value = None

    @property
    def is_required(self):
        return self._required

    @property
    def is_nullable(self):
        return self._nullable

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, new_value):
        self._value = new_value

    @abc.abstractmethod
    def validate(self):
        pass


class RequestMeta(type):

    def __new__(mcs, name, bases, attrs):
        _fields = []
        for attr_name, attr in attrs.items():
            if isinstance(attr, Field):
                attrs[attr_name].name = attr_name
                _fields.append(attr)
        cls = super().__new__(mcs, name, bases, attrs)
        cls._fields = _fields

        return cls


class Request(metaclass=RequestMeta):

    def __init__(self, request: Dict[str, Union[int, str, Dict[str, str], List[int]]]):
        if not request:
            raise ValueError

        self.not_empty_fields = []
        for field in self._fields:

            if field.name not in request and field.is_required:
                raise ValueError

            if field.name not in request:
                continue

            if not request[field.name] and not field.is_nullable:
                raise ValueError

            if request[field.name]:
                self.not_empty_fields.append(field.name)
            setattr(self, field.name, request[field.name])
        self.validate()

    def validate(self):
        pass


class CharField(Field):
    def validate(self):
        if not isinstance(self.value, str):
            raise ValueError


class ArgumentsField(Field):
    def validate(self):
        if not isinstance(self.value, dict):
            raise ValueError


class EmailField(CharField):
    def validate(self):
        if "@" not in self.value:
            raise ValueError


class PhoneField(Field):
    def validate(self):
        if not isinstance(self.value, (int, str)) and not re.match(r"7\d{10}", str(self.value)):
            raise ValueError


class DateField(Field):
    def validate(self):
        datetime.datetime.strptime(self.value, '%d.%m.%Y')


class BirthDayField(Field):

    def validate(self):
        birthday_date = datetime.datetime.strptime(self, '%d.%m.%Y')
        delta = datetime.datetime.now().year - birthday_date.year
        if 0 <= delta < 70:
            raise ValueError


class GenderField(Field):
    def validate(self):
        if self.value != UNKNOWN or self.value != MALE or self.value != FEMALE:
            raise ValueError


class ClientIDsField(Field):
    def validate(self):
        if not isinstance(self.value, list):
            raise ValueError
        for cid in self.value:
            if not isinstance(cid, int):
                raise ValueError


class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(Request):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    @property
    def has(self):
        return self.not_empty_fields

    @property
    def field_pairs(self):
        return [("phone", "email"), ("first_name", "last_name"), ("gender", "birthday")]

    def validate(self):
        for valid_field_pair in self.field_pairs:
            if all(field in self.not_empty_fields for field in valid_field_pair):
                break
        raise ValueError


class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode("utf-8")).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode("utf-8")).hexdigest()
    if digest == request.token:
        return True
    return False


def online_score_handler(method_request, ctx, store):

    if method_request.is_admin:
        return {"score": 42}, OK

    try:
        score_request = OnlineScoreRequest(method_request.arguments)
    except ValueError:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST

    ctx["has"] = score_request.has

    score = get_score(store=store, phone=score_request.phone, email=score_request.email,
                      birthday=score_request.birthday, gender=score_request.birthday,
                      first_name=score_request.first_name, last_name=score_request.last_name)

    return {"score": score}, OK


def clients_interests_handler(method_request, ctx, store):
    try:
        interests_request = ClientsInterestsRequest(method_request.arguments)
    except ValueError:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST

    interests = {}
    for cid in interests_request.client_ids:
        interests[cid] = get_interests(store, cid)

    ctx["nclients"] = len(interests_request.client_ids)

    return interests, OK


def method_handler(request, ctx, store):

    if isinstance(request, dict) and "body" not in request:
        return ERRORS[BAD_REQUEST], BAD_REQUEST
    try:
        method_request = MethodRequest(request["body"])
    except ValueError:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST

    if not check_auth(method_request):
        response, code = ERRORS[FORBIDDEN], FORBIDDEN
    elif method_request.method == "online_score":
        response, code = online_score_handler(method_request, ctx, store)
    elif method_request.method == "clients_interests":
        response, code = clients_interests_handler(method_request, ctx, store)
    else:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST

    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    @staticmethod
    def get_request_id(headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except Exception:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    parser = ArgumentParser(description='Process some integers.')
    parser.add_argument("-p", "--port", action="store", type=int, default=8080)
    parser.add_argument("-l", "--log", action="store", default=None)
    args = parser.parse_args()
    logging.basicConfig(filename=args.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", args.port), MainHTTPHandler)
    logging.info("Starting server at %s" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
