rule Win_Trojan_Mybot_5444
{
strings:
	$a0 = { 7792d6f2fba0b82fc2bcab0bcb185dc9b7441a99b4bb12c301dee0c178b719cd2e08051d0d70aedfa3ce35b2afbf5e93ef50b991eb8947ee90fc3c145d75bac604a086a209b664d5d15934bae9e207172f2bbf3c380d80e3ed48b8ddbe745d2305c30684d60cf3bd11 }

condition:
	$a0
}

        
