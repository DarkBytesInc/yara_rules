rule Win_Downloader_Small_4976
{
strings:
	$a0 = { c0672eeeb7b064164d0f040b8dfabbd2dcbd197050c2f698af40908a51bd80686f8cfa820b48bcc9a5d880f4d45f53919c11f8402020fac2bd8fd003fb9a7f332822184ea077b7942f07446fc886b7bceff1bd10bc48ebee500e34fb8a5e80c08c3c0fc1 }

condition:
	$a0
}

        
