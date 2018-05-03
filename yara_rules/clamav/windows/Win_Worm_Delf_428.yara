rule Win_Worm_Delf_428
{
strings:
	$a0 = { 4310ba6c5b4000e89fdbffff8d4314ba7c5b4000e892dbffff8d430cba9c5b4000e885dbffff8bc3e8aef8ffff8bc3e83bd2ffff5be82ddaffff00ffffffff060000006464646464640000ffffffff070000007373737373737300ffffffff140000006d7567656d737079 }

condition:
	$a0
}

        
