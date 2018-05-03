rule Osx_Tool_Rubilyn_2
{
strings:
	$a0 = { 2f7573722f7362696e2f73797363746c[10]64656275672e727562696c796e }
	$a1 = { 70726f63657373 }
	$a2 = { 68696465 }
	$a3 = { 6261636b646f6f72 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
