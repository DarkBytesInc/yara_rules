rule Win_Spyware_Banker_4571
{
strings:
	$a0 = { 87628a377c3b3cddae1c74441312b3c88036c5079c8d3ba71cfc2a499e89e16c78da724d5cc70d708a98e8f16c3e17b6722e920bf92b88c6f8e7eefbd21290cb4d0248ea30aed542822a12cea5fb4e6a88bc411c3decb86f5f1a5d6adab2930e1b6ce993 }

condition:
	$a0
}

        
