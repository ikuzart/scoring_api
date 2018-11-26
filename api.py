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


class ValidationError(Exception):
    pass


class Field:

    def __init__(self, required: bool, nullable: bool):
        self.required = required
        self.nullable = nullable

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, instance, owner):
        return instance.__dict__.get(self.name, None)

    def __set__(self, instance, value):
        self._validate(value)
        instance.__dict__[self.name] = value

    @staticmethod
    def _validate(value) -> bool:
        raise NotImplementedError


class RequestMeta(type):

    def __new__(mcs, name, bases, dct):
        cls = super().__new__(mcs, name, bases, dct)
        cls._fields = {}
        for attr_name, attr_value in dct.items():
            if not isinstance(attr_value, Field):
                continue
            cls._fields[attr_name] = attr_value

        return cls


class Request(metaclass=RequestMeta):

    def __init__(self, request: Dict[str, Union[int, str, Dict[str, str], List[int]]]):
        self.request = request
        self.not_empty_req_fields = []
        for field_name, field_value in self._fields.items():
            self._validate_request_field(field_name, field_value)
            if field_name not in request:
                continue
            setattr(self, field_name, request[field_name])
            self.not_empty_req_fields.append(field_name)

    def _validate_request_field(self, field_name: str, field_value: Field):
        if field_value.required and field_name not in self.request:
            raise ValidationError("No required field {} value".format(field_name))
        if not field_value.nullable and not self.request[field_name]:
            raise ValidationError("No value for not nullable field {}".format(field_name))


class CharField(Field):
    @staticmethod
    def _validate(value):
        if not isinstance(value, str):
            raise ValidationError("Value for {} not of a correct type".format(__name__))


class ArgumentsField(Field):
    @staticmethod
    def _validate(value):
        if not isinstance(value, dict):
            raise ValidationError("Value for {} not of a correct type".format(__name__))


class EmailField(CharField):
    @staticmethod
    def _validate(value):
        if "@" not in value:
            raise ValidationError("Field {} got invalid value".format(__name__))


class PhoneField(Field):
    @staticmethod
    def _validate(value):
        if not isinstance(value, (str, int)) or not re.match(r"7\d{10}", str(value)):
            raise ValidationError("Value for {} not of a correct type".format(__name__))


class DateField(Field):
    @staticmethod
    def _validate(value):
        try:
            datetime.datetime.strptime(value, '%d.%m.%Y')
        except ValueError:
            raise ValidationError("Date value for {} not of is incorrect".format(__name__))


class BirthDayField(Field):
    @staticmethod
    def _validate(value):
        try:
            birthday_date = datetime.datetime.strptime(value, '%d.%m.%Y')
        except ValueError:
            raise ValidationError("Date value for {} not of is incorrect".format(__name__))
        delta = datetime.datetime.now().year - birthday_date.year
        if delta > 70:
            raise ValidationError("Age is more than allowed value".format(__name__))


class GenderField(Field):
    @staticmethod
    def _validate(value):
        if value not in (UNKNOWN, MALE, FEMALE):
            raise ValidationError("Field {} got invalid value".format(__name__))


class ClientIDsField(Field):
    @staticmethod
    def _validate(value):
        if not isinstance(value, list):
            raise ValidationError("Value for {} not of a correct type".format(__name__))
        for cid in value:
            if not isinstance(cid, int):
                raise ValidationError("Field {} got invalid value".format(__name__))


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
        return self.not_empty_req_fields

    @property
    def field_pairs(self):
        return [("phone", "email"), ("first_name", "last_name"), ("gender", "birthday")]

    def __init__(self, request: Dict[str, Union[int, str, Dict[str, str], List[int]]]):
        super().__init__(request)
        self._validate_pairs()

    def _validate_pairs(self):
        for valid_field_pair in self.field_pairs:
            if all(field in self.not_empty_req_fields for field in valid_field_pair):
                return
        raise ValidationError("Do not have values for valid field pairs")


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
    except ValidationError as err:
        return str(err), INVALID_REQUEST

    ctx["has"] = score_request.has
    score = get_score(store=store, phone=score_request.phone, email=score_request.email,
                      birthday=score_request.birthday, gender=score_request.birthday,
                      first_name=score_request.first_name, last_name=score_request.last_name)
    return {"score": score}, OK


def clients_interests_handler(method_request, ctx, store):
    try:
        interests_request = ClientsInterestsRequest(method_request.arguments)
    except ValidationError as err:
        return str(err), INVALID_REQUEST

    interests = {}
    for cid in interests_request.client_ids:
        interests[cid] = get_interests(store, cid)

    ctx["nclients"] = len(interests_request.client_ids)

    return interests, OK


def method_handler(request, ctx, store):
    handlers = {"online_score": online_score_handler,
                "clients_interests": clients_interests_handler}

    if not request["body"]:
        return "Request body is empty", INVALID_REQUEST

    try:
        method_request = MethodRequest(request["body"])
    except ValidationError as err:
        return str(err), INVALID_REQUEST

    if not check_auth(method_request):
        return ERRORS[FORBIDDEN], FORBIDDEN

    handler = handlers.get(method_request.method)
    if not handler:
        return "No method handler for {}".format(method_request.method), INVALID_REQUEST
    response, code = handler(method_request, ctx, store)

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
