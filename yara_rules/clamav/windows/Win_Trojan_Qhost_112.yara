rule Win_Trojan_Qhost_112
{
strings:
	$a0 = { 65652e636f6d0d0a3132372e302e302e3120637573746f6d65722e73796d616e7465632e636f6d0d0a3132372e302e302e31206c6976657570646174652e73796d616e7465632e636f6d0d0a3132372e302e302e312075732e6d63616665652e636f6d0d0a3132372e302e302e3120757064617465732e73796d616e7465632e636f6d0d0a3132372e302e302e3120757064 }

condition:
	$a0
}

        