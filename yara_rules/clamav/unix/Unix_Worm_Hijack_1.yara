rule Unix_Worm_Hijack_1
{
strings:
	$a0 = { 2f746d702f2e746d702f7730726d7374617274203e2f6465762f6e756c6c20323e2631292026 }

condition:
	$a0
}

        
