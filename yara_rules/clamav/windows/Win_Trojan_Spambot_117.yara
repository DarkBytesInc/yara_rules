rule Win_Trojan_Spambot_117
{
strings:
	$a0 = { 907f577f00d013e843a51e31003bf12b9dea829867fffffeffc8078c39744342af3528d159dfe1361b21f8efd2d2565371e230b8dcd2ffffffffe79b984003a1dce8ddd7dea70e5a8174e4094736be0b253f8f795589acb14fbaffffffffb21541000355e721bc4f02e8c04efbba }

condition:
	$a0
}

        
