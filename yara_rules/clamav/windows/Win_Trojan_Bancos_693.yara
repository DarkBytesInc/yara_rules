rule Win_Trojan_Bancos_693
{
strings:
	$a0 = { 682e611b5ac59b5f0f24d5cdca5371bf565a35dc00eed9ddacb70147f526113c649d86e633b927d04875f6ba967180511762355bc5c54b926003abd3b13844b79938cfadef2fbe084bcd114c }

condition:
	$a0
}

        
