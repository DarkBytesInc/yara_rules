rule Win_Trojan_Small_136
{
strings:
	$a0 = { 8bfe0334a5b3388ec3bf0100af7511b165f3a48ed9be8400938704abad8704ab8eda8ec2c350b800422bc9cd2158 }

condition:
	$a0
}

        