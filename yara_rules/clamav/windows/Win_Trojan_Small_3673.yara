rule Win_Trojan_Small_3673
{
strings:
	$a0 = { 8283ff76fb7e6901672272630f6874c47073383a2f9dc25a00baff652d676f9dc1b22cfcc1543edf8e1ed53cbe005132310b6865690767d7da766be70cd735dee1c922 }

condition:
	$a0
}

        
