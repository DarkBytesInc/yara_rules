rule Win_Downloader_Small_1804
{
strings:
	$a0 = { 6c7b0d92b16fb26087a40e6b33a4e76ba666e75892cf27123fdf58f7ac68ac03100829ac160cb8b94734b2b937fc8bf88d174ef3903c0f6fece628b80911fab0933d63374c }
	$a1 = { 6374002400687474703a }

condition:
	$a0 and $a1
}

        
