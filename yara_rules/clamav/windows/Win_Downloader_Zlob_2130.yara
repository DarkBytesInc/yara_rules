rule Win_Downloader_Zlob_2130
{
strings:
	$a0 = { ea4ee2fa0f1665fb76fb4b775cb373b74e17173b0d2c71609bdea1c75cdef87a5bebac8713eeee10cea18b2f7c086b657a217154d999a6bbf73b6a94dd38b465c1b1c2186e5484e1ee99632bcdf7ed3a367ddbe366329b87bddc2e98f76a5b3f6eefbc2bbbf6770a72381add6003dfa8dbb4d4bd }

condition:
	$a0
}

        
