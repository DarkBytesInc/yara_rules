rule Html_Trojan_SmallBP_1
{
strings:
	$a0 = { 0a50485e6523c36d93ec27f4fd12db1e5e92f42612200af4023cd7e6434808200a0a751ccf6234366489da7ab565072effb71feceb989000436f6e7465022d747970653a20617070ffadbdfd6c6963617469152f6f63181773747265616d0090dbff1f6100687474703a2f2f62696e676f723a6fdf6eefb72e026d2f6d63 }

condition:
	$a0
}

        