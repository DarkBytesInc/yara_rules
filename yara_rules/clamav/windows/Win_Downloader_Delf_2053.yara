rule Win_Downloader_Delf_2053
{
strings:
	$a0 = { bc5ec3e04fae4b3ae83571b55cd0056ad024fbc045dd668b2ed08bea9266700361765015bcbdb812cdbca4a12a78346e337e46c3a1ae93d29db52429076397fb3125ee9a5dbb0b9ccc12ecadc41c1a1e180f0e1cd131236325fec6825fc6ba4cdc5ce2edf3226f7cf43d49ef9c7d3d7af30b9de80efee52334af20323e5b657c }

condition:
	$a0
}

        
