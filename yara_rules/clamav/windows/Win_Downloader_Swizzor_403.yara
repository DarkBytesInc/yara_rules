rule Win_Downloader_Swizzor_403
{
strings:
	$a0 = { f6ba3880cbf8b4b380072ff441fe75676596098d22d6448a03f171b0b711db2b257dac2bd2de7b0a3dfe5b6c337087d08df3757ca9e2f071483b601bcacab16750e59262070661eeb76d4f7412a7da79e3262bcdb87dbf4ff7fb }

condition:
	$a0
}

        
