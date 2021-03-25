from s3_sysbackup import quilting

from base64 import b64decode
from io import BytesIO
from should_dsl import should, should_not

example_source_data = b64decode("""
    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
""")

def test_consistent_zip_output():
    def construct_backup_blob_data():
        inf = BytesIO(example_source_data)
        return quilting._FilePrepStream(inf).stream_to(lambda _: None)
    
    result = construct_backup_blob_data()
    
    assert result.content_compressed
    result.aws_integrity() |should| equal_to('Te8fakDJEyFDSgBQ+2KLRw==')
