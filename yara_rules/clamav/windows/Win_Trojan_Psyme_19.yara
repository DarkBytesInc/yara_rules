rule Win_Trojan_Psyme_19
{
strings:
	$a0 = { 2b272f2f6d61696e272b272e63686d272b273a3a272b272f6d61272b27696e2e272b2768746d273b646f63756d656e742e777269746528636f6478772e7661 }

condition:
	$a0
}

        