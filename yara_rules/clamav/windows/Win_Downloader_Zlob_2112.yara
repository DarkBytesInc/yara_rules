rule Win_Downloader_Zlob_2112
{
strings:
	$a0 = { 3ed2105828ca6a4eccac09f8d23362c2ddcf3fd530bbf26da5edd4a4e72efa479e95bee991e4597261d367cf45cfca29dcbda776a859139a786e7cf81db5433eaa18702af0a3dbfe723bf9bae8879dc7e67aeefca5d1e797c71fdd50bf664fa0 }

condition:
	$a0
}

        
