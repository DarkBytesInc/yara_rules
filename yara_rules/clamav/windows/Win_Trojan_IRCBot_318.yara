rule Win_Trojan_IRCBot_318
{
strings:
	$a0 = { 4ccf585ff029974cef5769282b0c5aeb5e75447444bb48016c038972c98f5c87604f8052a40721abedef1106b2feb9fbfd1fd4ae0cc7090b0d22d3328dd7d9dbfd331071b5b4ac1bdcd08028fb250c7f1c2e14f70b351c }

condition:
	$a0
}

        
