rule Win_Trojan_Qhost_111
{
strings:
	$a0 = { 372e302e302e3109096674702e662d7365637572652e636f6d0d0a3132372e302e302e3109096674702e736f70686f732e636f6d0d0a3132372e302e302e310909676f2e6d6963726f736f66742e636f6d0d0a3132372e302e302e3109096c6976657570646174652e73796d616e7465632e636f6d0d0a3132372e302e302e3109096d6173742e6d636166 }

condition:
	$a0
}

        