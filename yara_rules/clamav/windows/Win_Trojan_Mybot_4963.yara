rule Win_Trojan_Mybot_4963
{
strings:
	$a0 = { ee451559f52aa7f037006d9a40610cd0fa41ff89ccc880a0d5d4774996af9e00da589fa29d88c579fd3b7ec23f05309e8c50f8589fafe0b8f2f4d3e26706132c2424fe460c382862d2cf0eb796e4 }

condition:
	$a0
}

        
