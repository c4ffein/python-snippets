import mimetypes
from binascii import hexlify
from itertools import chain
from os import urandom


class MultiPartForm:
    # TODO : Clean and document
    def __init__(self):
        self.form_fields = []
        self.files = []
        self.boundary = hexlify(urandom(16))

    def add_field(self, name, value):
        self.form_fields.append((name, value))

    def add_file(self, field_name, file_name, file_handle, mimetype=None):
        body = file_handle.read()
        mimetype = (mimetypes.guess_type(file_name)[0] or "application/octet-stream") if mimetype is None else mimetypes
        self.files.append((field_name, file_name, mimetype, body))

    def __bytes__(self):
        part_boundary = b"--" + self.boundary
        gen_disposition = lambda name: f'Content-Disposition: form-data; name="{name}"'.encode(encoding="ascii")
        gen_file = lambda field, file: gen_disposition(field) + f'; filename="{file}"'.encode(encoding="ascii")
        gen_content_type = lambda content_type: f"Content-Type: {content_type}".encode(encoding="ascii")
        forms_to_add = ([part_boundary, gen_disposition(name), b"", value] for name, value in self.form_fields)
        files_to_add = (
            [part_boundary, gen_file(field_name, file_name), gen_content_type(content_type), b"", body]
            for field_name, file_name, content_type, body in self.files
        )
        return b"\r\n".join([*chain(*(chain(forms_to_add, files_to_add))), b"--" + self.boundary + b"--", b""])
