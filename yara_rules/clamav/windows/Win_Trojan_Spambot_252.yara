rule Win_Trojan_Spambot_252
{
strings:
	$a0 = { 90eb89c86eff7544a87cf5321ad39088628bf2c615feb215a6372a05affad9ffffffff27d48336e6ef8d770eb42138ec40cade9a1f3c32f4f0aff6b3923f08707bb66df4ffffff14a73354632f86f6e38685d5cdc911c1f43959e48efea9f70208e562ffffff7fa143a3dc909e9d }

condition:
	$a0
}

        
