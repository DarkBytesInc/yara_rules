rule Win_Worm_StrationWH_1
{
strings:
	$a0 = { 1253a3e3ff02d1f5e4c4f5fde0c0f1e4f82643f9ff6fff7f50616974426d68614a656961450411667d607144667b77716767db1bffff5971797b666d }

condition:
	$a0
}

        
