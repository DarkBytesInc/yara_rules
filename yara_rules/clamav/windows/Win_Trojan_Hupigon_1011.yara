rule Win_Trojan_Hupigon_1011
{
strings:
	$a0 = { 8a6ba00011d6dba413080f81c030fb5ed0aec1c6fa307a0a676830bede104f3b0265b6a88d9528ed3eacaa3b72ee705ebdc51c916c042aa1843f7adb6fbfd70b056f6fdc1e1b11161705ac85ec3519b69781bf16bf7e005d5b4bf94c6d38e17712fb09ebcf33a3bcfc }

condition:
	$a0
}

        
