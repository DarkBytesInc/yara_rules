rule Win_Trojan_Mybot_7979
{
strings:
	$a0 = { c739a8867de9ef2be3e8252d658a1aa0706f63947602bb3cbfff2fdfbddcaf4f4699161883547c40e59511245f3e7e37faf108271ddee8b42e4ce29a1afe65e95c3e57b58293daf510efaa242a98d053022bf3f555a0fd2bacd69234152ddbf6da71cad7d1c6bbde61a3313fbde3 }

condition:
	$a0
}

        
