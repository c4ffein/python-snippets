import io
import unittest

from src.multi_part_form import MultiPartForm


class TestMultiPartForm(unittest.TestCase):
    def test_init_creates_boundary(self):
        """Test that initialization creates a boundary."""
        form = MultiPartForm()
        self.assertIsNotNone(form.boundary)
        self.assertEqual(len(form.boundary), 32)  # hexlify(urandom(16)) = 32 chars
        self.assertEqual(form.form_fields, [])
        self.assertEqual(form.files, [])

    def test_add_field(self):
        """Test adding form fields."""
        form = MultiPartForm()
        form.add_field("username", b"testuser")
        form.add_field("email", b"test@example.com")
        self.assertEqual(len(form.form_fields), 2)
        self.assertEqual(form.form_fields[0], ("username", b"testuser"))
        self.assertEqual(form.form_fields[1], ("email", b"test@example.com"))

    def test_add_file_with_explicit_mimetype(self):
        """Test adding a file with explicit mimetype."""
        form = MultiPartForm()
        file_content = b"test file content"
        file_handle = io.BytesIO(file_content)
        form.add_file("document", "test.txt", file_handle, mimetype="text/plain")
        self.assertEqual(len(form.files), 1)
        field_name, file_name, mimetype, body = form.files[0]
        self.assertEqual(field_name, "document")
        self.assertEqual(file_name, "test.txt")
        self.assertEqual(mimetype, "text/plain")
        self.assertEqual(body, file_content)

    def test_add_file_with_guessed_mimetype(self):
        """Test adding a file with guessed mimetype."""
        form = MultiPartForm()
        file_content = b"test file content"
        file_handle = io.BytesIO(file_content)
        form.add_file("document", "test.txt", file_handle)
        self.assertEqual(len(form.files), 1)
        field_name, file_name, mimetype, body = form.files[0]
        self.assertEqual(field_name, "document")
        self.assertEqual(file_name, "test.txt")
        self.assertEqual(mimetype, "text/plain")
        self.assertEqual(body, file_content)

    def test_add_file_with_unknown_extension(self):
        """Test adding a file with unknown extension defaults to application/octet-stream."""
        form = MultiPartForm()
        file_content = b"binary content"
        file_handle = io.BytesIO(file_content)
        form.add_file("binary", "test.unknown", file_handle)
        self.assertEqual(len(form.files), 1)
        field_name, file_name, mimetype, body = form.files[0]
        self.assertEqual(mimetype, "application/octet-stream")

    def test_bytes_with_only_fields(self):
        """Test encoding with only form fields."""
        form = MultiPartForm()
        form.add_field("field1", b"value1")
        form.add_field("field2", b"value2")
        result = bytes(form)
        # Check boundary markers
        self.assertIn(b"--" + form.boundary, result)
        self.assertIn(b"--" + form.boundary + b"--", result)
        # Check field content
        self.assertIn(b'Content-Disposition: form-data; name="field1"', result)
        self.assertIn(b'Content-Disposition: form-data; name="field2"', result)
        self.assertIn(b"value1", result)
        self.assertIn(b"value2", result)
        # Check CRLF line endings
        self.assertIn(b"\r\n", result)

    def test_bytes_with_only_files(self):
        """Test encoding with only files."""
        form = MultiPartForm()
        file_content = b"test file content"
        file_handle = io.BytesIO(file_content)
        form.add_file("upload", "test.txt", file_handle, mimetype="text/plain")
        result = bytes(form)
        # Check boundary markers
        self.assertIn(b"--" + form.boundary, result)
        self.assertIn(b"--" + form.boundary + b"--", result)
        # Check file content
        self.assertIn(b'Content-Disposition: form-data; name="upload"; filename="test.txt"', result)
        self.assertIn(b"Content-Type: text/plain", result)
        self.assertIn(file_content, result)

    def test_bytes_with_fields_and_files(self):
        """Test encoding with both form fields and files."""
        form = MultiPartForm()
        form.add_field("username", b"testuser")
        file_content = b"test file content"
        file_handle = io.BytesIO(file_content)
        form.add_file("document", "test.txt", file_handle)
        result = bytes(form)
        # Check both field and file content
        self.assertIn(b'Content-Disposition: form-data; name="username"', result)
        self.assertIn(b"testuser", result)
        self.assertIn(b'Content-Disposition: form-data; name="document"; filename="test.txt"', result)
        self.assertIn(file_content, result)

    def test_bytes_ends_with_closing_boundary(self):
        """Test that the byte representation ends with proper closing boundary."""
        form = MultiPartForm()
        form.add_field("test", b"value")
        result = bytes(form)
        # Should end with closing boundary and CRLF
        self.assertTrue(result.endswith(b"--" + form.boundary + b"--\r\n"))

    def test_multiple_files(self):
        """Test adding multiple files."""
        form = MultiPartForm()
        file1_content = b"first file"
        file1_handle = io.BytesIO(file1_content)
        form.add_file("file1", "test1.txt", file1_handle)
        file2_content = b"second file"
        file2_handle = io.BytesIO(file2_content)
        form.add_file("file2", "test2.jpg", file2_handle, mimetype="image/jpeg")
        self.assertEqual(len(form.files), 2)
        result = bytes(form)
        self.assertIn(file1_content, result)
        self.assertIn(file2_content, result)
        self.assertIn(b"image/jpeg", result)

    def test_boundary_uniqueness(self):
        """Test that different instances have different boundaries."""
        form1 = MultiPartForm()
        form2 = MultiPartForm()
        self.assertNotEqual(form1.boundary, form2.boundary)

    def test_empty_form(self):
        """Test encoding an empty form."""
        form = MultiPartForm()
        result = bytes(form)
        # Should still have closing boundary
        self.assertIn(b"--" + form.boundary + b"--", result)


if __name__ == "__main__":
    unittest.main()
