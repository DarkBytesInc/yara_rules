rule Win_Ircbot_Lazirc_3
{
strings:
	$a0 = { 5c77696e646f77735c73797374656d0d0a617474726962206d6f70726f6e2e7a6970202d72202d68202d730d0a636f7079206d6f70726f6e2e7a697020633a5c6d79736578797e312e7a69700d0a617474726962206d6f70726f6e2e7a6970202b72202b68202b730d0a636c730d0a }

condition:
	$a0
}

        